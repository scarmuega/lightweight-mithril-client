//! A client which retrieves and validates certificates from an Aggregator.
//!
//! In order to do so it defines a [CertificateClient] exposes the following features:
//!  - [get][CertificateClient::get]: get a certificate data from its hash
//!  - [list][CertificateClient::list]: get the list of available certificates
//!  - [verify_chain][CertificateClient::verify_chain]: verify a certificate chain
//!
//! # Get a certificate
//!
//! To get a certificate using the [ClientBuilder][crate::client::ClientBuilder].
//!
//! ```no_run
//! # async fn run() -> mithril_client::MithrilResult<()> {
//! use mithril_client::ClientBuilder;
//!
//! let client = ClientBuilder::aggregator("YOUR_AGGREGATOR_ENDPOINT", "YOUR_GENESIS_VERIFICATION_KEY").build()?;
//! let certificate = client.certificate().get("CERTIFICATE_HASH").await?.unwrap();
//!
//! println!("Certificate hash={}, signed_message={}", certificate.hash, certificate.signed_message);
//! #    Ok(())
//! # }
//! ```
//!
//! # List available certificates
//!
//! To list available certificates using the [ClientBuilder][crate::client::ClientBuilder].
//!
//! ```no_run
//! # async fn run() -> mithril_client::MithrilResult<()> {
//! use mithril_client::ClientBuilder;
//!
//! let client = mithril_client::ClientBuilder::aggregator("YOUR_AGGREGATOR_ENDPOINT", "YOUR_GENESIS_VERIFICATION_KEY").build()?;
//! let certificates = client.certificate().list().await?;
//!
//! for certificate in certificates {
//!     println!("Certificate hash={}, signed_message={}", certificate.hash, certificate.signed_message);
//! }
//! #    Ok(())
//! # }
//! ```
//!
//! # Validate a certificate chain
//!
//! To validate a certificate using the [ClientBuilder][crate::client::ClientBuilder].
//!
//! ```no_run
//! # async fn run() -> mithril_client::MithrilResult<()> {
//! use mithril_client::ClientBuilder;
//!
//! let client = ClientBuilder::aggregator("YOUR_AGGREGATOR_ENDPOINT", "YOUR_GENESIS_VERIFICATION_KEY").build()?;
//! let certificate = client.certificate().verify_chain("CERTIFICATE_HASH").await?;
//!
//! println!("Chain of Certificate (hash: {}) is valid", certificate.hash);
//! #    Ok(())
//! # }
//! ```

use std::sync::Arc;

use anyhow::{anyhow, Context};
use async_trait::async_trait;
use slog::{crit, debug, Logger};

use crate::aggregator_client::{AggregatorClient, AggregatorClientError, AggregatorRequest};
use crate::common::crypto_helper::ProtocolGenesisVerificationKey;
use crate::common::{
    certificate_chain::{
        CertificateRetriever, CertificateRetrieverError,
        CertificateVerifier as CommonCertificateVerifier,
        MithrilCertificateVerifier as CommonMithrilCertificateVerifier,
    },
    entities::Certificate,
    messages::CertificateMessage,
};
use crate::feedback::{FeedbackSender, MithrilEvent};
use crate::{MithrilCertificate, MithrilCertificateListItem, MithrilResult};

#[cfg(test)]
use mockall::automock;

/// Aggregator client for the Certificate
pub struct CertificateClient {
    aggregator_client: Arc<dyn AggregatorClient>,
    retriever: Arc<InternalCertificateRetriever>,
    verifier: Arc<dyn CertificateVerifier>,
}

/// API that defines how to validate certificates.
#[cfg_attr(test, automock)]
#[cfg_attr(target_family = "wasm", async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait)]
pub trait CertificateVerifier: Sync + Send {
    /// Validate the chain starting with the given certificate.
    async fn verify_chain(&self, certificate: &MithrilCertificate) -> MithrilResult<()>;
}

impl CertificateClient {
    /// Constructs a new `CertificateClient`.
    pub fn new(
        aggregator_client: Arc<dyn AggregatorClient>,
        verifier: Arc<dyn CertificateVerifier>,
        logger: Logger,
    ) -> Self {
        let retriever = Arc::new(InternalCertificateRetriever {
            aggregator_client: aggregator_client.clone(),
            logger,
        });

        Self {
            aggregator_client,
            retriever,
            verifier,
        }
    }

    /// Fetch a list of certificates
    pub async fn list(&self) -> MithrilResult<Vec<MithrilCertificateListItem>> {
        let response = self
            .aggregator_client
            .get_content(AggregatorRequest::ListCertificates)
            .await
            .with_context(|| "CertificateClient can not get the certificate list")?;
        let items = serde_json::from_str::<Vec<MithrilCertificateListItem>>(&response)
            .with_context(|| "CertificateClient can not deserialize certificate list")?;

        Ok(items)
    }

    /// Get a single certificate full information from the aggregator.
    pub async fn get(&self, certificate_hash: &str) -> MithrilResult<Option<MithrilCertificate>> {
        self.retriever.get(certificate_hash).await
    }

    /// Validate the chain starting with the certificate with given `certificate_hash`, return the certificate if
    /// the chain is valid.
    ///
    /// This method will fail if no certificate exists for the given `certificate_hash`.
    pub async fn verify_chain(&self, certificate_hash: &str) -> MithrilResult<MithrilCertificate> {
        let certificate = self.retriever.get(certificate_hash).await?.ok_or(anyhow!(
            "No certificate exist for hash '{certificate_hash}'"
        ))?;

        self.verifier
            .verify_chain(&certificate)
            .await
            .with_context(|| {
                format!("Certicate chain of certificate '{certificate_hash}' is invalid")
            })?;

        Ok(certificate)
    }
}

/// Internal type to implement the [InternalCertificateRetriever] trait and avoid a circular
/// dependency between the [CertificateClient] and the [CommonMithrilCertificateVerifier] that need
/// a [CertificateRetriever] as a dependency.
struct InternalCertificateRetriever {
    aggregator_client: Arc<dyn AggregatorClient>,
    logger: Logger,
}

impl InternalCertificateRetriever {
    async fn get(&self, certificate_hash: &str) -> MithrilResult<Option<MithrilCertificate>> {
        let response = self
            .aggregator_client
            .get_content(AggregatorRequest::GetCertificate {
                hash: certificate_hash.to_string(),
            })
            .await;

        match response {
            Err(AggregatorClientError::RemoteServerLogical(_)) => Ok(None),
            Err(e) => Err(e.into()),
            Ok(response) => {
                let message =
                    serde_json::from_str::<CertificateMessage>(&response).map_err(|e| {
                        crit!(
                            self.logger,
                            "Could not create certificate from API message: {e}."
                        );
                        debug!(self.logger, "Certificate message = {response}");
                        e
                    })?;

                Ok(Some(message))
            }
        }
    }
}

/// Implementation of a [CertificateVerifier] that can send feedbacks using
/// the [feedback][crate::feedback] mechanism.
pub struct MithrilCertificateVerifier {
    internal_verifier: Arc<dyn CommonCertificateVerifier>,
    genesis_verification_key: ProtocolGenesisVerificationKey,
    feedback_sender: FeedbackSender,
}

impl MithrilCertificateVerifier {
    /// Constructs a new `MithrilCertificateVerifier`.
    pub fn new(
        aggregator_client: Arc<dyn AggregatorClient>,
        genesis_verification_key: &str,
        feedback_sender: FeedbackSender,
        logger: Logger,
    ) -> MithrilResult<MithrilCertificateVerifier> {
        let retriever = Arc::new(InternalCertificateRetriever {
            aggregator_client: aggregator_client.clone(),
            logger: logger.clone(),
        });
        let internal_verifier = Arc::new(CommonMithrilCertificateVerifier::new(
            logger,
            retriever.clone(),
        ));
        let genesis_verification_key =
            ProtocolGenesisVerificationKey::try_from(genesis_verification_key)
                .with_context(|| "Invalid genesis verification key")?;

        Ok(Self {
            internal_verifier,
            genesis_verification_key,
            feedback_sender,
        })
    }
}

#[cfg_attr(target_family = "wasm", async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait)]
impl CertificateVerifier for MithrilCertificateVerifier {
    async fn verify_chain(&self, certificate: &MithrilCertificate) -> MithrilResult<()> {
        // Todo: move most of this code in the `mithril_common` verifier by defining
        // a new `verify_chain` method that take a callback called when a certificate is
        // validated.
        let certificate_chain_validation_id = MithrilEvent::new_certificate_chain_validation_id();
        self.feedback_sender
            .send_event(MithrilEvent::CertificateChainValidationStarted {
                certificate_chain_validation_id: certificate_chain_validation_id.clone(),
            })
            .await;

        let mut current_certificate = certificate.clone().try_into()?;
        loop {
            let previous_or_none = self
                .internal_verifier
                .verify_certificate(&current_certificate, &self.genesis_verification_key)
                .await?;

            self.feedback_sender
                .send_event(MithrilEvent::CertificateValidated {
                    certificate_hash: current_certificate.hash.clone(),
                    certificate_chain_validation_id: certificate_chain_validation_id.clone(),
                })
                .await;

            match previous_or_none {
                Some(previous_certificate) => current_certificate = previous_certificate,
                None => break,
            }
        }

        self.feedback_sender
            .send_event(MithrilEvent::CertificateChainValidated {
                certificate_chain_validation_id,
            })
            .await;

        Ok(())
    }
}

#[cfg_attr(target_family = "wasm", async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait)]
impl CertificateRetriever for InternalCertificateRetriever {
    async fn get_certificate_details(
        &self,
        certificate_hash: &str,
    ) -> Result<Certificate, CertificateRetrieverError> {
        self.get(certificate_hash)
            .await
            .map_err(CertificateRetrieverError)?
            .map(|message| message.try_into())
            .transpose()
            .map_err(CertificateRetrieverError)?
            .ok_or(CertificateRetrieverError(anyhow!(format!(
                "Certificate does not exist: '{}'",
                certificate_hash
            ))))
    }
}
