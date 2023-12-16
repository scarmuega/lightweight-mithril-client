use crate::common::digesters::ImmutableFile;
use crate::common::entities::ImmutableFileNumber;
use crate::common::{StdError, StdResult};
use anyhow::{anyhow, Context};
use async_trait::async_trait;
use std::ops::Add;
use std::path::PathBuf;
use thiserror::Error;
use tokio::sync::RwLock;

/// Retrieve data on [ImmutableFile] from a cardano database.
#[async_trait]
pub trait ImmutableFileObserver
where
    Self: Sync + Send,
{
    /// Get the [ImmutableFileNumber] of the last immutable file in the cardano database.
    async fn get_last_immutable_number(&self) -> StdResult<u64>;
}

/// [ImmutableFileObserver] related errors.
#[derive(Error, Debug)]
pub enum ImmutableFileObserverError {
    /// Raised when the no immutables files were available.
    #[error("no immutable file was returned")]
    Missing(),

    /// Raised when [immutable file listing][ImmutableFile::list_completed_in_dir] fails.
    #[error("immutable file creation error")]
    ImmutableFileListing(#[source] StdError),
}

/// An [ImmutableFileObserver] using the filesystem.
pub struct ImmutableFileSystemObserver {
    db_path: PathBuf,
}

impl ImmutableFileSystemObserver {
    /// [ImmutableFileSystemObserver] factory.
    pub fn new(db_path: &PathBuf) -> Self {
        let db_path = db_path.to_owned();

        Self { db_path }
    }
}

#[async_trait]
impl ImmutableFileObserver for ImmutableFileSystemObserver {
    async fn get_last_immutable_number(&self) -> StdResult<u64> {
        let immutable_file_number = ImmutableFile::list_completed_in_dir(&self.db_path)
            .map_err(|e| anyhow!(e))
            .with_context(|| "Immutable File System Observer can not list all immutable files")?
            .into_iter()
            .last()
            .ok_or(anyhow!(ImmutableFileObserverError::Missing()))?
            .number;

        Ok(immutable_file_number)
    }
}

/// An [ImmutableFileObserver] yielding fixed results for tests purpose.
pub struct DumbImmutableFileObserver {
    /// The [ImmutableFileNumber] that shall be returned by
    /// [get_last_immutable_number][ImmutableFileObserver::get_last_immutable_number]
    pub shall_return: RwLock<Option<ImmutableFileNumber>>,
}

impl Default for DumbImmutableFileObserver {
    fn default() -> Self {
        let mut observer = Self::new();
        observer.shall_return = RwLock::new(Some(500));

        observer
    }
}

impl DumbImmutableFileObserver {
    /// [DumbImmutableFileObserver] factory.
    pub fn new() -> Self {
        Self {
            shall_return: RwLock::new(None),
        }
    }

    /// Update the stored [immutable file number][DumbImmutableFileObserver::shall_return].
    pub async fn shall_return(&self, what: Option<u64>) -> &Self {
        let mut shall_return = self.shall_return.write().await;
        *shall_return = what;
        self
    }

    /// Increase by one the stored [immutable file number][DumbImmutableFileObserver::shall_return],
    /// return the updated value.
    pub async fn increase(&self) -> StdResult<u64> {
        let new_number = self
            .shall_return
            .write()
            .await
            .ok_or_else(|| anyhow!(ImmutableFileObserverError::Missing()))?
            .add(1);
        self.shall_return(Some(new_number)).await;

        Ok(new_number)
    }
}

#[async_trait]
impl ImmutableFileObserver for DumbImmutableFileObserver {
    async fn get_last_immutable_number(&self) -> StdResult<u64> {
        self.shall_return
            .read()
            .await
            .ok_or_else(|| anyhow!(ImmutableFileObserverError::Missing()))
    }
}

#[cfg(test)]
mod tests {}
