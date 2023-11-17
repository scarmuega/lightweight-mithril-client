//! This service is responsible of provinding HTTP server with messages as fast as possible.

use std::sync::Arc;

use async_trait::async_trait;
use thiserror::Error;

use mithril_common::{
    messages::{CertificateListMessage, CertificateMessage, CertificatePendingMessage},
    StdResult,
};

use crate::database::provider::CertificateMessageRepository;

/// Error related to the [HttpMessageService]
#[derive(Debug, Error)]
pub enum HttpMessageServiceError {
    /// There is no current PendingCertificate
    #[error("There is no current pending certificate.")]
    PendingCertificateDoesNotExist,
}
/// HTTP Message service trait.
#[async_trait]
pub trait HttpMessageService {
    /// Return the message representation of a certificate if it exists.
    async fn get_certificate(
        &self,
        certificate_hash: &str,
    ) -> StdResult<Option<CertificateMessage>>;

    /// Return the message representation of the last N certificates
    async fn get_last_certificates(&self, limit: usize) -> StdResult<CertificateListMessage>;

    /// Return the message representation of the current pending certificate
    async fn get_pending_certificate(&self) -> StdResult<CertificatePendingMessage>;
}

pub struct MithrilHttpMessageService {
    certificate_message_repository: Arc<CertificateMessageRepository>,
}

impl MithrilHttpMessageService {
    pub fn new(certificate_message_repository: Arc<CertificateMessageRepository>) -> Self {
        Self {
            certificate_message_repository,
        }
    }
}

#[async_trait]
impl HttpMessageService for MithrilHttpMessageService {
    async fn get_certificate(
        &self,
        certificate_hash: &str,
    ) -> StdResult<Option<CertificateMessage>> {
        self.certificate_message_repository
            .get_certificate(certificate_hash)
            .await
    }

    async fn get_last_certificates(&self, limit: usize) -> StdResult<CertificateListMessage> {
        self.certificate_message_repository.get_last(limit).await
    }

    async fn get_pending_certificate(&self) -> StdResult<CertificatePendingMessage> {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use mithril_common::{entities::Beacon, test_utils::MithrilFixtureBuilder};

    use crate::{dependency_injection::DependenciesBuilder, Configuration};

    use super::*;

    #[tokio::test]
    async fn get_no_certificate() {
        // setup
        let configuration = Configuration::new_sample();
        let mut dep_builder = DependenciesBuilder::new(configuration);
        let service = dep_builder.get_http_message_service().await.unwrap();

        // test
        let certificate_hash = "whatever";
        let certficate_message = service.get_certificate(certificate_hash).await.unwrap();
        assert!(certficate_message.is_none());
    }

    #[tokio::test]
    async fn get_certificate() {
        // setup
        let configuration = Configuration::new_sample();
        let mut dep_builder = DependenciesBuilder::new(configuration);
        let service = dep_builder.get_http_message_service().await.unwrap();
        let beacon = Beacon::new("devnet".to_string(), 3, 1);
        let fixture = MithrilFixtureBuilder::default().with_signers(3).build();
        let genesis_beacon = Beacon {
            epoch: beacon.epoch - 1,
            ..beacon.clone()
        };
        let genesis_certificate = fixture.create_genesis_certificate(&genesis_beacon);
        dep_builder
            .get_certificate_repository()
            .await
            .unwrap()
            .create_certificate(genesis_certificate.clone())
            .await
            .unwrap();

        // test
        let certficate_message = service
            .get_certificate(&genesis_certificate.hash)
            .await
            .unwrap()
            .expect("There should be a certificate.");
        assert_eq!(genesis_certificate.hash, certficate_message.hash);
    }

    #[tokio::test]
    async fn get_last_certificates() {
        let configuration = Configuration::new_sample();
        let mut dep_builder = DependenciesBuilder::new(configuration);
        let service = dep_builder.get_http_message_service().await.unwrap();
        let beacon = Beacon::new("devnet".to_string(), 3, 1);
        let fixture = MithrilFixtureBuilder::default().with_signers(3).build();
        let genesis_beacon = Beacon {
            epoch: beacon.epoch - 1,
            ..beacon.clone()
        };
        let genesis_certificate = fixture.create_genesis_certificate(&genesis_beacon);
        dep_builder
            .get_certificate_repository()
            .await
            .unwrap()
            .create_certificate(genesis_certificate.clone())
            .await
            .unwrap();

        // test
        let certficate_messages = service.get_last_certificates(5).await.unwrap();
        assert_eq!(genesis_certificate.hash, certficate_messages[0].hash);
    }
}
