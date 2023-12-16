use super::super::entities;
use super::types;
use crate::common::crypto_helper::{ProtocolPartyId, ProtocolStake};

impl From<types::ProtocolParameters> for entities::ProtocolParameters {
    fn from(other: types::ProtocolParameters) -> Self {
        entities::ProtocolParameters::new(other.k, other.m, other.phi_f)
    }
}

impl From<entities::ProtocolParameters> for types::ProtocolParameters {
    fn from(other: entities::ProtocolParameters) -> Self {
        types::ProtocolParameters {
            k: other.k,
            m: other.m,
            phi_f: other.phi_f,
        }
    }
}

impl From<&entities::SignerWithStake> for (types::ProtocolPartyId, types::ProtocolStake) {
    fn from(other: &entities::SignerWithStake) -> Self {
        (
            other.party_id.clone() as ProtocolPartyId,
            other.stake as ProtocolStake,
        )
    }
}
