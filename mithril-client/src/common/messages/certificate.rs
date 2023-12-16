use anyhow::Context;
use serde::{Deserialize, Serialize};
use std::fmt::{Debug, Formatter};

use crate::common::entities::{
    Beacon, Certificate, CertificateMetadata, CertificateSignature, ProtocolMessage,
};
use crate::common::messages::CertificateMetadataMessagePart;
use crate::common::StdError;

/// Message structure of a certificate
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct CertificateMessage {
    /// Hash of the current certificate
    /// Computed from the other fields of the certificate
    /// aka H(Cp,n))
    pub hash: String,

    /// Hash of the previous certificate in the chain
    /// This is either the hash of the first certificate of the epoch in the chain
    /// Or the first certificate of the previous epoch in the chain (if the certificate is the first of its epoch)
    /// aka H(FC(n))
    pub previous_hash: String,

    /// Mithril beacon on the Cardano chain
    /// aka BEACON(p,n)
    pub beacon: Beacon,

    /// Certificate metadata
    /// aka METADATA(p,n)
    pub metadata: CertificateMetadataMessagePart,

    /// Structured message that is used to created the signed message
    /// aka MSG(p,n) U AVK(n-1)
    pub protocol_message: ProtocolMessage,

    /// Message that is signed by the signers
    /// aka H(MSG(p,n) || AVK(n-1))
    pub signed_message: String,

    /// Aggregate verification key
    /// The AVK used to sign during the current epoch
    /// aka AVK(n-2)
    pub aggregate_verification_key: String,

    /// STM multi signature created from a quorum of single signatures from the signers
    /// aka MULTI_SIG(H(MSG(p,n) || AVK(n-1)))
    pub multi_signature: String,

    /// Genesis signature created from the original stake distribution
    /// aka GENESIS_SIG(AVK(-1))
    pub genesis_signature: String,
}

impl CertificateMessage {
    /// Check that the certificate signed message match the given protocol message.
    pub fn match_message(&self, message: &ProtocolMessage) -> bool {
        message.compute_hash() == self.signed_message
    }
}

impl Debug for CertificateMessage {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let should_be_exhaustive = f.alternate();
        let mut debug = f.debug_struct("Certificate");
        debug
            .field("hash", &self.hash)
            .field("previous_hash", &self.previous_hash)
            .field("beacon", &format_args!("{:?}", self.beacon))
            .field("metadata", &format_args!("{:?}", self.metadata))
            .field(
                "protocol_message",
                &format_args!("{:?}", self.protocol_message),
            )
            .field("signed_message", &self.signed_message);

        match should_be_exhaustive {
            true => debug
                .field(
                    "aggregate_verification_key",
                    &self.aggregate_verification_key,
                )
                .field("multi_signature", &self.multi_signature)
                .field("genesis_signature", &self.genesis_signature)
                .finish(),
            false => debug.finish_non_exhaustive(),
        }
    }
}

impl TryFrom<CertificateMessage> for Certificate {
    type Error = StdError;

    fn try_from(certificate_message: CertificateMessage) -> Result<Self, Self::Error> {
        let metadata = CertificateMetadata {
            protocol_version: certificate_message.metadata.protocol_version,
            protocol_parameters: certificate_message.metadata.protocol_parameters,
            initiated_at: certificate_message.metadata.initiated_at,
            sealed_at: certificate_message.metadata.sealed_at,
            signers: certificate_message.metadata.signers,
        };

        let certificate = Certificate {
            hash: certificate_message.hash,
            previous_hash: certificate_message.previous_hash,
            beacon: certificate_message.beacon,
            metadata,
            protocol_message: certificate_message.protocol_message,
            signed_message: certificate_message.signed_message,
            aggregate_verification_key: certificate_message
                .aggregate_verification_key
                .try_into()
                .with_context(|| {
                "Can not convert message to certificate: can not decode the aggregate verification key"
            })?,
            signature: if certificate_message.genesis_signature.is_empty() {
                CertificateSignature::MultiSignature(
                    certificate_message
                        .multi_signature
                        .try_into()
                        .with_context(|| {
                            "Can not convert message to certificate: can not decode the multi-signature"
                        })?,
                )
            } else {
                CertificateSignature::GenesisSignature(
                    certificate_message
                        .genesis_signature
                        .try_into()
                        .with_context(|| {
                            "Can not convert message to certificate: can not decode the genesis signature"
                        })?,
                )
            },
        };

        Ok(certificate)
    }
}

impl TryFrom<Certificate> for CertificateMessage {
    type Error = StdError;

    fn try_from(certificate: Certificate) -> Result<Self, Self::Error> {
        let metadata = CertificateMetadataMessagePart {
            protocol_version: certificate.metadata.protocol_version,
            protocol_parameters: certificate.metadata.protocol_parameters,
            initiated_at: certificate.metadata.initiated_at,
            sealed_at: certificate.metadata.sealed_at,
            signers: certificate.metadata.signers,
        };

        let (multi_signature, genesis_signature) = match certificate.signature {
            CertificateSignature::GenesisSignature(signature) => {
                (String::new(), signature.to_bytes_hex())
            }
            CertificateSignature::MultiSignature(signature) => (
                signature.to_json_hex().with_context(|| {
                    "Can not convert certificate to message: can not encode the multi-signature"
                })?,
                String::new(),
            ),
        };

        let message = CertificateMessage {
            hash: certificate.hash,
            previous_hash: certificate.previous_hash,
            beacon: certificate.beacon,
            metadata,
            protocol_message: certificate.protocol_message,
            signed_message: certificate.signed_message,
            aggregate_verification_key: certificate
                .aggregate_verification_key
                .to_json_hex()
                .with_context(|| {
                    "Can not convert certificate to message: can not encode aggregate verification key"
                })?,
            multi_signature,
            genesis_signature,
        };

        Ok(message)
    }
}
