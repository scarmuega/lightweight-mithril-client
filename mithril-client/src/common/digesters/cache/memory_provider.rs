use crate::common::{
    digesters::cache::CacheProviderResult,
    digesters::cache::ImmutableFileDigestCacheProvider,
    digesters::ImmutableFile,
    entities::{HexEncodedDigest, ImmutableFileName},
};

use async_trait::async_trait;
use std::collections::{BTreeMap, HashMap};
use tokio::sync::RwLock;

/// A in memory [ImmutableFileDigestCacheProvider].
pub struct MemoryImmutableFileDigestCacheProvider {
    store: RwLock<HashMap<ImmutableFileName, HexEncodedDigest>>,
}

impl MemoryImmutableFileDigestCacheProvider {
    /// Build a new [MemoryImmutableFileDigestCacheProvider] that contains the given values.
    pub fn from(values: HashMap<ImmutableFileName, HexEncodedDigest>) -> Self {
        Self {
            store: RwLock::new(values),
        }
    }
}

impl Default for MemoryImmutableFileDigestCacheProvider {
    fn default() -> Self {
        Self {
            store: RwLock::new(HashMap::new()),
        }
    }
}

#[async_trait]
impl ImmutableFileDigestCacheProvider for MemoryImmutableFileDigestCacheProvider {
    async fn store(
        &self,
        digest_per_filenames: Vec<(ImmutableFileName, HexEncodedDigest)>,
    ) -> CacheProviderResult<()> {
        let mut store = self.store.write().await;
        for (filename, digest) in digest_per_filenames {
            store.insert(filename, digest);
        }

        Ok(())
    }

    async fn get(
        &self,
        immutables: Vec<ImmutableFile>,
    ) -> CacheProviderResult<BTreeMap<ImmutableFile, Option<HexEncodedDigest>>> {
        let store = self.store.read().await;
        let mut result = BTreeMap::new();

        for immutable in immutables {
            let value = store.get(&immutable.filename).map(|f| f.to_owned());
            result.insert(immutable, value);
        }

        Ok(result)
    }

    async fn reset(&self) -> CacheProviderResult<()> {
        let mut store = self.store.write().await;
        store.clear();
        Ok(())
    }
}
