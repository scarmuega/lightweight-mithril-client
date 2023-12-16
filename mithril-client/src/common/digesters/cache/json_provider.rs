use crate::common::{
    digesters::{
        cache::provider::{ImmutableDigesterCacheGetError, ImmutableDigesterCacheStoreError},
        cache::CacheProviderResult,
        cache::ImmutableFileDigestCacheProvider,
        ImmutableFile,
    },
    entities::{HexEncodedDigest, ImmutableFileName},
};

use async_trait::async_trait;
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};
#[cfg(feature = "fs")]
use tokio::{
    fs,
    fs::File,
    io::{AsyncReadExt, AsyncWriteExt},
};

type InnerStructure = BTreeMap<ImmutableFileName, HexEncodedDigest>;

/// A in memory [ImmutableFileDigestCacheProvider].
pub struct JsonImmutableFileDigestCacheProvider {
    filepath: PathBuf,
}

impl JsonImmutableFileDigestCacheProvider {
    /// [JsonImmutableFileDigestCacheProvider] factory
    pub fn new(filepath: &Path) -> Self {
        Self {
            filepath: filepath.to_path_buf(),
        }
    }

    #[cfg(test)]
    /// [Test Only] Build a new [JsonImmutableFileDigestCacheProvider] that contains the given values.
    pub async fn from(filepath: &Path, values: InnerStructure) -> Self {
        let provider = Self::new(filepath);
        provider.write_data(values).await.unwrap();
        provider
    }

    async fn write_data(
        &self,
        values: InnerStructure,
    ) -> Result<(), ImmutableDigesterCacheStoreError> {
        let mut file = File::create(&self.filepath).await?;
        file.write_all(serde_json::to_string_pretty(&values)?.as_bytes())
            .await?;

        Ok(())
    }

    async fn read_data(&self) -> Result<InnerStructure, ImmutableDigesterCacheGetError> {
        match self.filepath.exists() {
            true => {
                let mut file = File::open(&self.filepath).await?;
                let mut json_string = String::new();
                file.read_to_string(&mut json_string).await?;
                let values: InnerStructure = serde_json::from_str(&json_string)?;
                Ok(values)
            }
            false => Ok(BTreeMap::new()),
        }
    }
}

#[async_trait]
impl ImmutableFileDigestCacheProvider for JsonImmutableFileDigestCacheProvider {
    async fn store(
        &self,
        digest_per_filenames: Vec<(ImmutableFileName, HexEncodedDigest)>,
    ) -> CacheProviderResult<()> {
        let mut data = self.read_data().await?;
        for (filename, digest) in digest_per_filenames {
            data.insert(filename, digest);
        }
        self.write_data(data).await?;

        Ok(())
    }

    async fn get(
        &self,
        immutables: Vec<ImmutableFile>,
    ) -> CacheProviderResult<BTreeMap<ImmutableFile, Option<HexEncodedDigest>>> {
        let values = self.read_data().await?;
        let mut result = BTreeMap::new();

        for immutable in immutables {
            let value = values.get(&immutable.filename).map(|f| f.to_owned());
            result.insert(immutable, value);
        }

        Ok(result)
    }

    async fn reset(&self) -> CacheProviderResult<()> {
        fs::remove_file(&self.filepath)
            .await
            .map_err(ImmutableDigesterCacheStoreError::from)?;

        Ok(())
    }
}
