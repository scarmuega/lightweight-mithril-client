use crate::common::crypto_helper::{
    ProtocolAggregateVerificationKey, ProtocolGenesisSignature, ProtocolMultiSignature,
};
use crate::common::entities::{Beacon, CertificateMetadata, ProtocolMessage};
use std::cmp::Ordering;
use std::fmt::{Debug, Formatter};

use sha2::{Digest, Sha256};

/// The signature of a [Certificate]
#[derive(Clone, Debug)]
pub enum CertificateSignature {
    /// Genesis signature created from the original stake distribution
    /// aka GENESIS_SIG(AVK(-1))
    GenesisSignature(ProtocolGenesisSignature),

    /// STM multi signature created from a quorum of single signatures from the signers
    /// aka MULTI_SIG(H(MSG(p,n) || AVK(n-1)))
    MultiSignature(ProtocolMultiSignature),
}

/// Certificate represents a Mithril certificate embedding a Mithril STM multisignature
#[derive(Clone)]
pub struct Certificate {
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
    pub metadata: CertificateMetadata,

    /// Structured message that is used to created the signed message
    /// aka MSG(p,n) U AVK(n-1)
    pub protocol_message: ProtocolMessage,

    /// Message that is signed by the signers
    /// aka H(MSG(p,n) || AVK(n-1))
    pub signed_message: String,

    /// Aggregate verification key
    /// The AVK used to sign during the current epoch
    /// aka AVK(n-2)
    pub aggregate_verification_key: ProtocolAggregateVerificationKey,

    /// Certificate signature
    pub signature: CertificateSignature,
}

impl Certificate {
    /// Certificate factory
    pub fn new(
        previous_hash: String,
        beacon: Beacon,
        metadata: CertificateMetadata,
        protocol_message: ProtocolMessage,
        aggregate_verification_key: ProtocolAggregateVerificationKey,
        signature: CertificateSignature,
    ) -> Certificate {
        let signed_message = protocol_message.compute_hash();
        let mut certificate = Certificate {
            hash: "".to_string(),
            previous_hash,
            beacon,
            metadata,
            protocol_message,
            signed_message,
            aggregate_verification_key,
            signature,
        };
        certificate.hash = certificate.compute_hash();
        certificate
    }

    /// Computes the hash of a Certificate
    pub fn compute_hash(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.previous_hash.as_bytes());
        hasher.update(self.beacon.compute_hash().as_bytes());
        hasher.update(self.metadata.compute_hash().as_bytes());
        hasher.update(self.protocol_message.compute_hash().as_bytes());
        hasher.update(self.signed_message.as_bytes());
        hasher.update(
            self.aggregate_verification_key
                .to_json_hex()
                .unwrap()
                .as_bytes(),
        );
        match &self.signature {
            CertificateSignature::GenesisSignature(signature) => {
                hasher.update(signature.to_bytes_hex());
            }
            CertificateSignature::MultiSignature(signature) => {
                hasher.update(&signature.to_json_hex().unwrap());
            }
        };
        hex::encode(hasher.finalize())
    }

    /// Tell if the certificate is a genesis certificate
    pub fn is_genesis(&self) -> bool {
        matches!(self.signature, CertificateSignature::GenesisSignature(_))
    }

    /// Return true if the certificate is chaining into itself (meaning that its hash and previous
    /// hash are equal).
    pub fn is_chaining_to_itself(&self) -> bool {
        self.hash == self.previous_hash
    }

    /// Check that the certificate signed message match the given protocol message.
    pub fn match_message(&self, message: &ProtocolMessage) -> bool {
        message.compute_hash() == self.signed_message
    }
}

impl PartialEq for Certificate {
    fn eq(&self, other: &Self) -> bool {
        self.beacon.eq(&other.beacon) && self.hash.eq(&other.hash)
    }
}

impl PartialOrd for Certificate {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        // Order by beacon first then per hash
        match self.beacon.partial_cmp(&other.beacon) {
            Some(Ordering::Equal) => self.hash.partial_cmp(&other.hash),
            Some(other) => Some(other),
            // Beacons may be not comparable (most likely because the network isn't the same) in
            // that case we can still order per hash
            None => self.hash.partial_cmp(&other.hash),
        }
    }
}

impl Debug for Certificate {
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
                    &format_args!("{:?}", self.aggregate_verification_key),
                )
                .field("signature", &format_args!("{:?}", self.signature))
                .finish(),
            false => debug.finish_non_exhaustive(),
        }
    }
}
