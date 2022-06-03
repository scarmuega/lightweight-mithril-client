use super::{AdapterError, StoreAdapter};
use async_trait::async_trait;
use std::marker::PhantomData;

pub struct FailStoreAdapter<K, R> {
    key: PhantomData<K>,
    certificate: PhantomData<R>,
}

#[cfg(test)]
impl<K, R> FailStoreAdapter<K, R> {
    pub fn new() -> Self {
        Self {
            key: PhantomData,
            certificate: PhantomData,
        }
    }
}

#[async_trait]
impl<K, R> StoreAdapter for FailStoreAdapter<K, R>
where
    R: Clone + Send + Sync,
    K: PartialEq + Clone + Send + Sync,
{
    type Key = K;
    type Record = R;

    async fn store_record(
        &mut self,
        _key: &Self::Key,
        _record: &Self::Record,
    ) -> Result<(), AdapterError> {
        Err(AdapterError::GeneralError("an error occurred".to_string()))
    }

    async fn get_record(&self, _key: &Self::Key) -> Result<Option<Self::Record>, AdapterError> {
        Err(AdapterError::GeneralError("an error occurred".to_string()))
    }

    async fn record_exists(&self, _key: &Self::Key) -> Result<bool, AdapterError> {
        Err(AdapterError::GeneralError("an error occurred".to_string()))
    }

    async fn get_last_n_records(
        &self,
        _how_many: usize,
    ) -> Result<Vec<(Self::Key, Self::Record)>, AdapterError> {
        Err(AdapterError::GeneralError("an error occurred".to_string()))
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[tokio::test]
    async fn test_with_no_record_exists() {
        let adapter: FailStoreAdapter<u64, String> = FailStoreAdapter::new();

        assert!(adapter.record_exists(&1).await.is_err());
    }

    #[tokio::test]
    async fn test_with_no_record_get() {
        let adapter: FailStoreAdapter<u64, String> = FailStoreAdapter::new();

        assert!(adapter.get_record(&1).await.is_err());
    }

    #[tokio::test]
    async fn test_write_record() {
        let mut adapter: FailStoreAdapter<u64, String> = FailStoreAdapter::new();

        assert!(adapter
            .store_record(&1, &"record".to_string())
            .await
            .is_err());
    }

    #[tokio::test]
    async fn test_list() {
        let adapter: FailStoreAdapter<u64, String> = FailStoreAdapter::new();

        assert!(adapter.get_last_n_records(10).await.is_err());
    }

    #[tokio::test]
    async fn test_list_with_records() {
        let mut adapter: FailStoreAdapter<u64, String> = FailStoreAdapter::new();
        assert!(adapter
            .store_record(&1, &"record".to_string())
            .await
            .is_err());
    }

    #[tokio::test]
    async fn test_list_with_last_zero() {
        let adapter: FailStoreAdapter<u64, String> = FailStoreAdapter::new();
        assert!(adapter.get_last_n_records(0).await.is_err());
    }
}