//! A module used to validate the Certificate Chain created by an aggregator
//!
use anyhow::{anyhow, Context};
use async_trait::async_trait;
use hex::ToHex;
use slog::{debug, Logger};
use std::sync::Arc;
use thiserror::Error;

use super::CertificateRetriever;
use crate::common::crypto_helper::{
    ProtocolAggregateVerificationKey, ProtocolGenesisError, ProtocolGenesisVerificationKey,
    ProtocolMultiSignature,
};
use crate::common::entities::{
    Certificate, CertificateSignature, ProtocolMessage, ProtocolMessagePartKey, ProtocolParameters,
};
use crate::common::StdResult;

#[cfg(test)]
use mockall::automock;

/// [CertificateVerifier] related errors.
#[derive(Error, Debug)]
pub enum CertificateVerifierError {
    /// Error raised when the multi signatures verification fails.
    #[error("multi signature verification failed: '{0}'")]
    VerifyMultiSignature(String),

    /// Error raised when the Genesis Signature stored in a [Certificate] is invalid.
    #[error("certificate genesis error")]
    CertificateGenesis(#[from] ProtocolGenesisError),

    /// Error raised when the hash stored in a [Certificate] doesn't match a recomputed hash.
    #[error("certificate hash unmatch error")]
    CertificateHashUnmatch,

    /// Error raised when validating the certificate chain if a previous [Certificate] hash isn't
    /// equal to the current certificate `previous_hash`.
    #[error("certificate chain previous hash unmatch error")]
    CertificateChainPreviousHashUnmatch,

    /// Error raised when validating the certificate chain if the current [Certificate]
    /// `aggregate_verification_key` doesn't match the previous `aggregate_verification_key` (if
    /// the certificates are on the same epoch) or the previous `next_aggregate_verification_key`
    /// (if the certificates are on different epoch).
    #[error("certificate chain AVK unmatch error")]
    CertificateChainAVKUnmatch,

    /// Error raised when validating the certificate chain if the chain loops.
    #[error("certificate chain infinite loop error")]
    CertificateChainInfiniteLoop,

    /// Error raised when [CertificateVerifier::verify_genesis_certificate] was called with a
    /// certificate that's not a genesis certificate.
    #[error("can't validate genesis certificate: given certificate isn't a genesis certificate")]
    InvalidGenesisCertificateProvided,
}

/// CertificateVerifier is the cryptographic engine in charge of verifying multi signatures and
/// [certificates](Certificate)
#[cfg_attr(test, automock)]
#[cfg_attr(target_family = "wasm", async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait)]
pub trait CertificateVerifier: Send + Sync {
    /// Verify Genesis certificate
    async fn verify_genesis_certificate(
        &self,
        genesis_certificate: &Certificate,
        genesis_verification_key: &ProtocolGenesisVerificationKey,
    ) -> StdResult<()>;

    /// Verify if a Certificate is valid and returns the previous Certificate in the chain if exists
    /// Step 1: Check if the hash is valid (i.e. the Certificate has not been tampered by modifying its content)
    /// Step 2: Check that the multi signature is valid if it is a Standard Certificate (i.e verification of the Mithril multi signature)
    /// Step 3: Check that the aggregate verification key of the Certificate is registered in the previous Certificate in the chain
    async fn verify_certificate(
        &self,
        certificate: &Certificate,
        genesis_verification_key: &ProtocolGenesisVerificationKey,
    ) -> StdResult<Option<Certificate>>;

    /// Verify that the Certificate Chain associated to a Certificate is valid
    /// TODO: see if we can borrow the certificate instead.
    async fn verify_certificate_chain(
        &self,
        certificate: Certificate,
        genesis_verification_key: &ProtocolGenesisVerificationKey,
    ) -> StdResult<()> {
        let mut certificate = certificate;
        while let Some(previous_certificate) = self
            .verify_certificate(&certificate, genesis_verification_key)
            .await?
        {
            certificate = previous_certificate;
        }

        Ok(())
    }

    /// still a dirty hack to mock the protocol message
    /// verify that the protocol message is equal to the signed message of the certificate.
    /// TODO: Remove this method.
    fn verify_protocol_message(
        &self,
        protocol_message: &ProtocolMessage,
        certificate: &Certificate,
    ) -> bool {
        protocol_message.compute_hash() == certificate.signed_message
    }
}

/// MithrilCertificateVerifier is an implementation of the CertificateVerifier
pub struct MithrilCertificateVerifier {
    /// The logger where the logs should be written
    logger: Logger,
    certificate_retriever: Arc<dyn CertificateRetriever>,
}

impl MithrilCertificateVerifier {
    /// MithrilCertificateVerifier factory
    pub fn new(logger: Logger, certificate_retriever: Arc<dyn CertificateRetriever>) -> Self {
        debug!(logger, "New MithrilCertificateVerifier created");
        Self {
            logger,
            certificate_retriever,
        }
    }

    /// Verify a multi signature
    fn verify_multi_signature(
        &self,
        message: &[u8],
        multi_signature: &ProtocolMultiSignature,
        aggregate_verification_key: &ProtocolAggregateVerificationKey,
        protocol_parameters: &ProtocolParameters,
    ) -> Result<(), CertificateVerifierError> {
        debug!(
            self.logger,
            "Verify multi signature for {:?}",
            message.encode_hex::<String>()
        );

        multi_signature
            .verify(
                message,
                aggregate_verification_key,
                &protocol_parameters.to_owned().into(),
            )
            .map_err(|e| CertificateVerifierError::VerifyMultiSignature(e.to_string()))
    }

    /// Verify Standard certificate
    async fn verify_standard_certificate(
        &self,
        certificate: &Certificate,
        signature: &ProtocolMultiSignature,
    ) -> StdResult<Option<Certificate>> {
        self.verify_multi_signature(
            certificate.signed_message.as_bytes(),
            signature,
            &certificate.aggregate_verification_key,
            &certificate.metadata.protocol_parameters,
        )?;
        let previous_certificate = self
            .certificate_retriever
            .get_certificate_details(&certificate.previous_hash)
            .await
            .map_err(|e| anyhow!(e))
            .with_context(|| "Can not retrieve previous certificate during verification")?;

        if previous_certificate.hash != certificate.previous_hash {
            return Err(anyhow!(
                CertificateVerifierError::CertificateChainPreviousHashUnmatch
            ));
        }

        let current_certificate_avk: String = certificate
            .aggregate_verification_key
            .to_json_hex()
            .with_context(|| {
                format!(
                    "avk to string conversion error for certificate: `{}`",
                    certificate.hash
                )
            })?;

        let previous_certificate_avk: String = previous_certificate
            .aggregate_verification_key
            .to_json_hex()
            .with_context(|| {
                format!(
                    "avk to string conversion error for previous certificate: `{}`",
                    certificate.hash
                )
            })?;

        let valid_certificate_has_different_epoch_as_previous =
            |next_aggregate_verification_key: &str| -> bool {
                next_aggregate_verification_key == current_certificate_avk
                    && previous_certificate.beacon.epoch != certificate.beacon.epoch
            };
        let valid_certificate_has_same_epoch_as_previous = || -> bool {
            previous_certificate_avk == current_certificate_avk
                && previous_certificate.beacon.epoch == certificate.beacon.epoch
        };

        match previous_certificate
            .protocol_message
            .get_message_part(&ProtocolMessagePartKey::NextAggregateVerificationKey)
        {
            Some(next_aggregate_verification_key)
                if valid_certificate_has_different_epoch_as_previous(
                    next_aggregate_verification_key,
                ) =>
            {
                Ok(Some(previous_certificate.to_owned()))
            }
            Some(_) if valid_certificate_has_same_epoch_as_previous() => {
                Ok(Some(previous_certificate.to_owned()))
            }
            None => Ok(None),
            _ => {
                debug!(
                    self.logger,
                    "Previous certificate {:#?}", previous_certificate
                );
                Err(anyhow!(
                    CertificateVerifierError::CertificateChainAVKUnmatch
                ))
            }
        }
    }
}

#[cfg_attr(target_family = "wasm", async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait)]
impl CertificateVerifier for MithrilCertificateVerifier {
    /// Verify Genesis certificate
    async fn verify_genesis_certificate(
        &self,
        genesis_certificate: &Certificate,
        genesis_verification_key: &ProtocolGenesisVerificationKey,
    ) -> StdResult<()> {
        let genesis_signature = match &genesis_certificate.signature {
            CertificateSignature::GenesisSignature(signature) => Ok(signature),
            _ => Err(CertificateVerifierError::InvalidGenesisCertificateProvided),
        }?;

        genesis_verification_key
            .verify(
                genesis_certificate.signed_message.as_bytes(),
                genesis_signature,
            )
            .with_context(|| "Certificate verifier failed verifying a genesis certificate")?;

        Ok(())
    }

    /// Verify a certificate
    async fn verify_certificate(
        &self,
        certificate: &Certificate,
        genesis_verification_key: &ProtocolGenesisVerificationKey,
    ) -> StdResult<Option<Certificate>> {
        debug!(
            self.logger,
            "Verifying certificate";
            "certificate_hash" => &certificate.hash,
            "certificate_previous_hash" => &certificate.previous_hash,
            "certificate_beacon" => ?certificate.beacon
        );

        certificate
            .hash
            .eq(&certificate.compute_hash())
            .then(|| certificate.hash.clone())
            .ok_or(CertificateVerifierError::CertificateHashUnmatch)?;

        if certificate.is_chaining_to_itself() {
            Err(anyhow!(
                CertificateVerifierError::CertificateChainInfiniteLoop
            ))
        } else {
            match &certificate.signature {
                CertificateSignature::GenesisSignature(_signature) => {
                    self.verify_genesis_certificate(certificate, genesis_verification_key)
                        .await?;
                    Ok(None)
                }
                CertificateSignature::MultiSignature(signature) => {
                    self.verify_standard_certificate(certificate, signature)
                        .await
                }
            }
        }
    }
}
