use crate::common::{
    crypto_helper::{
        KESPeriod, ProtocolOpCert, ProtocolSignerVerificationKey,
        ProtocolSignerVerificationKeySignature,
    },
    entities::{PartyId, Stake},
};
use std::fmt::{Debug, Formatter};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Signer represents a signing participant in the network
#[derive(Clone, Eq, Serialize, Deserialize)]
pub struct Signer {
    /// The unique identifier of the signer
    // TODO: Should be removed once the signer certification is fully deployed
    pub party_id: PartyId,

    /// The public key used to authenticate signer signature
    pub verification_key: ProtocolSignerVerificationKey,

    /// The encoded signer 'Mithril verification key' signature (signed by the Cardano node KES secret key)
    // TODO: Option should be removed once the signer certification is fully deployed
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verification_key_signature: Option<ProtocolSignerVerificationKeySignature>,

    /// The encoded operational certificate of stake pool operator attached to the signer node
    // TODO: Option should be removed once the signer certification is fully deployed
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operational_certificate: Option<ProtocolOpCert>,

    /// The kes period used to compute the verification key signature
    // TODO: This kes period shoud not be used as is and should probably be within an allowed range of kes period for the epoch
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kes_period: Option<KESPeriod>,
}

impl PartialEq for Signer {
    fn eq(&self, other: &Self) -> bool {
        self.party_id.eq(&other.party_id)
    }
}

impl Signer {
    /// Signer factory
    pub fn new(
        party_id: PartyId,
        verification_key: ProtocolSignerVerificationKey,
        verification_key_signature: Option<ProtocolSignerVerificationKeySignature>,
        operational_certificate: Option<ProtocolOpCert>,
        kes_period: Option<KESPeriod>,
    ) -> Signer {
        Signer {
            party_id,
            verification_key,
            verification_key_signature,
            operational_certificate,
            kes_period,
        }
    }

    /// Convert the given values to a vec of signers.
    pub fn vec_from<T: Into<Signer>>(from: Vec<T>) -> Vec<Self> {
        from.into_iter().map(|f| f.into()).collect()
    }

    /// Computes the hash of Signer
    pub fn compute_hash(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.party_id.as_bytes());
        hasher.update(self.verification_key.to_json_hex().unwrap().as_bytes());

        if let Some(verification_key_signature) = &self.verification_key_signature {
            hasher.update(verification_key_signature.to_json_hex().unwrap().as_bytes());
        }
        if let Some(operational_certificate) = &self.operational_certificate {
            hasher.update(operational_certificate.to_json_hex().unwrap().as_bytes());
        }
        hex::encode(hasher.finalize())
    }
}

impl Debug for Signer {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let should_be_exhaustive = f.alternate();
        let mut debug = f.debug_struct("Signer");
        debug.field("party_id", &self.party_id);

        match should_be_exhaustive {
            true => debug
                .field(
                    "verification_key",
                    &format_args!("{:?}", self.verification_key),
                )
                .field(
                    "verification_key_signature",
                    &format_args!("{:?}", self.verification_key_signature),
                )
                .field(
                    "operational_certificate",
                    &format_args!("{:?}", self.operational_certificate),
                )
                .field("kes_period", &format_args!("{:?}", self.kes_period))
                .finish(),
            false => debug.finish_non_exhaustive(),
        }
    }
}

impl From<SignerWithStake> for Signer {
    fn from(other: SignerWithStake) -> Self {
        Signer::new(
            other.party_id,
            other.verification_key,
            other.verification_key_signature,
            other.operational_certificate,
            other.kes_period,
        )
    }
}

/// Signer represents a signing party in the network (including its stakes)
#[derive(Clone, Eq, Serialize, Deserialize)]
pub struct SignerWithStake {
    /// The unique identifier of the signer
    // TODO: Should be removed once the signer certification is fully deployed
    pub party_id: PartyId,

    /// The public key used to authenticate signer signature
    pub verification_key: ProtocolSignerVerificationKey,

    /// The encoded signer 'Mithril verification key' signature (signed by the Cardano node KES secret key)
    // TODO: Option should be removed once the signer certification is fully deployed
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verification_key_signature: Option<ProtocolSignerVerificationKeySignature>,

    /// The encoded operational certificate of stake pool operator attached to the signer node
    // TODO: Option should be removed once the signer certification is fully deployed
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operational_certificate: Option<ProtocolOpCert>,

    /// The kes period used to compute the verification key signature
    // TODO: This kes period shoud not be used as is and should probably be within an allowed range of kes period for the epoch
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kes_period: Option<KESPeriod>,

    /// The signer stake
    pub stake: Stake,
}

impl PartialEq for SignerWithStake {
    fn eq(&self, other: &Self) -> bool {
        self.party_id.eq(&other.party_id)
    }
}

impl PartialOrd for SignerWithStake {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for SignerWithStake {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.party_id.cmp(&other.party_id)
    }
}

impl SignerWithStake {
    /// SignerWithStake factory
    pub fn new(
        party_id: PartyId,
        verification_key: ProtocolSignerVerificationKey,
        verification_key_signature: Option<ProtocolSignerVerificationKeySignature>,
        operational_certificate: Option<ProtocolOpCert>,
        kes_period: Option<KESPeriod>,
        stake: Stake,
    ) -> SignerWithStake {
        SignerWithStake {
            party_id,
            verification_key,
            verification_key_signature,
            operational_certificate,
            kes_period,
            stake,
        }
    }

    /// Turn a [Signer] into a [SignerWithStake].
    pub fn from_signer(signer: Signer, stake: Stake) -> Self {
        Self {
            party_id: signer.party_id,
            verification_key: signer.verification_key,
            verification_key_signature: signer.verification_key_signature,
            operational_certificate: signer.operational_certificate,
            kes_period: signer.kes_period,
            stake,
        }
    }

    /// Computes the hash of SignerWithStake
    pub fn compute_hash(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.party_id.as_bytes());
        hasher.update(self.verification_key.to_json_hex().unwrap().as_bytes());

        if let Some(verification_key_signature) = &self.verification_key_signature {
            hasher.update(verification_key_signature.to_json_hex().unwrap().as_bytes());
        }

        if let Some(operational_certificate) = &self.operational_certificate {
            hasher.update(operational_certificate.to_json_hex().unwrap().as_bytes());
        }
        hasher.update(self.stake.to_be_bytes());
        hex::encode(hasher.finalize())
    }
}

impl Debug for SignerWithStake {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let should_be_exhaustive = f.alternate();
        let mut debug = f.debug_struct("SignerWithStake");
        debug
            .field("party_id", &self.party_id)
            .field("stake", &self.stake);

        match should_be_exhaustive {
            true => debug
                .field(
                    "verification_key",
                    &format_args!("{:?}", self.verification_key),
                )
                .field(
                    "verification_key_signature",
                    &format_args!("{:?}", self.verification_key_signature),
                )
                .field(
                    "operational_certificate",
                    &format_args!("{:?}", self.operational_certificate),
                )
                .field("kes_period", &format_args!("{:?}", self.kes_period))
                .finish(),
            false => debug.finish_non_exhaustive(),
        }
    }
}
