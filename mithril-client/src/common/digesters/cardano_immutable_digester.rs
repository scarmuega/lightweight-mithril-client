use crate::common::{
    digesters::{
        cache::ImmutableFileDigestCacheProvider, ImmutableDigester, ImmutableDigesterError,
        ImmutableFile,
    },
    entities::{Beacon, HexEncodedDigest, ImmutableFileName},
};
use async_trait::async_trait;
use sha2::{Digest, Sha256};
use slog::{debug, info, warn, Logger};
use std::{collections::BTreeMap, io, path::Path, sync::Arc};

/// Result of a cache computation, contains the digest and the list of new entries to add
/// to the [ImmutableFileDigestCacheProvider].
type CacheComputationResult =
    Result<([u8; 32], Vec<(ImmutableFileName, HexEncodedDigest)>), io::Error>;

/// A digester working directly on a Cardano DB immutables files
pub struct CardanoImmutableDigester {
    /// A [ImmutableFileDigestCacheProvider] instance
    cache_provider: Option<Arc<dyn ImmutableFileDigestCacheProvider>>,

    /// The logger where the logs should be written
    logger: Logger,
}

impl CardanoImmutableDigester {
    /// ImmutableDigester factory
    pub fn new(
        cache_provider: Option<Arc<dyn ImmutableFileDigestCacheProvider>>,
        logger: Logger,
    ) -> Self {
        Self {
            cache_provider,
            logger,
        }
    }
}

#[async_trait]
impl ImmutableDigester for CardanoImmutableDigester {
    async fn compute_digest(
        &self,
        dirpath: &Path,
        beacon: &Beacon,
    ) -> Result<String, ImmutableDigesterError> {
        let up_to_file_number = beacon.immutable_file_number;
        let immutables = ImmutableFile::list_completed_in_dir(dirpath)?
            .into_iter()
            .filter(|f| f.number <= up_to_file_number)
            .collect::<Vec<_>>();

        match immutables.last() {
            None => Err(ImmutableDigesterError::NotEnoughImmutable {
                expected_number: up_to_file_number,
                found_number: None,
                db_dir: dirpath.to_owned(),
            }),
            Some(last_immutable_file) if last_immutable_file.number < up_to_file_number => {
                Err(ImmutableDigesterError::NotEnoughImmutable {
                    expected_number: up_to_file_number,
                    found_number: Some(last_immutable_file.number),
                    db_dir: dirpath.to_owned(),
                })
            }
            Some(_) => {
                info!(self.logger, "#compute_digest"; "beacon" => #?beacon, "nb_of_immutables" => immutables.len());

                let cached_values = match self.cache_provider.as_ref() {
                    None => BTreeMap::from_iter(immutables.into_iter().map(|i| (i, None))),
                    Some(cache_provider) => match cache_provider.get(immutables.clone()).await {
                        Ok(values) => values,
                        Err(error) => {
                            warn!(
                                self.logger,
                                "Error while getting cached immutable files digests: {}", error
                            );
                            BTreeMap::from_iter(immutables.into_iter().map(|i| (i, None)))
                        }
                    },
                };

                // digest is done in a separate thread because it is blocking the whole task
                let logger = self.logger.clone();
                let thread_beacon = beacon.clone();
                let (hash, new_cache_entries) =
                    tokio::task::spawn_blocking(move || -> CacheComputationResult {
                        compute_hash(logger, &thread_beacon, cached_values)
                    })
                    .await
                    .map_err(|e| ImmutableDigesterError::DigestComputationError(e.into()))??;
                let digest = hex::encode(hash);

                debug!(self.logger, "#computed digest: {:?}", digest);

                if let Some(cache_provider) = self.cache_provider.as_ref() {
                    if let Err(error) = cache_provider.store(new_cache_entries).await {
                        warn!(
                            self.logger,
                            "Error while storing new immutable files digests to cache: {}", error
                        );
                    }
                }

                Ok(digest)
            }
        }
    }
}

fn compute_hash(
    logger: Logger,
    beacon: &Beacon,
    entries: BTreeMap<ImmutableFile, Option<HexEncodedDigest>>,
) -> CacheComputationResult {
    let mut hasher = Sha256::new();
    let mut new_cached_entries = Vec::new();
    let mut progress = Progress {
        index: 0,
        total: entries.len(),
    };

    hasher.update(beacon.compute_hash().as_bytes());

    for (ix, (entry, cache)) in entries.iter().enumerate() {
        match cache {
            None => {
                let data = hex::encode(entry.compute_raw_hash::<Sha256>()?);
                hasher.update(&data);
                new_cached_entries.push((entry.filename.clone(), data));
            }
            Some(digest) => {
                hasher.update(digest);
            }
        };

        if progress.report(ix) {
            info!(logger, "hashing: {}", &progress);
        }
    }

    Ok((hasher.finalize().into(), new_cached_entries))
}

struct Progress {
    index: usize,
    total: usize,
}

impl Progress {
    fn report(&mut self, ix: usize) -> bool {
        self.index = ix;
        (20 * ix) % self.total == 0
    }

    fn percent(&self) -> f64 {
        (self.index as f64 * 100.0 / self.total as f64).ceil()
    }
}

impl std::fmt::Display for Progress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(f, "{}/{} ({}%)", self.index, self.total, self.percent())
    }
}
