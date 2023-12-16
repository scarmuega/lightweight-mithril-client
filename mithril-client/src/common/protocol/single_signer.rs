use crate::common::{
    crypto_helper::ProtocolSigner,
    entities::{PartyId, ProtocolMessage, SingleSignatures},
    StdResult,
};

/// The SingleSigner is the structure responsible for issuing SingleSignatures.
#[cfg_attr(test, derive(Debug))]
pub struct SingleSigner {
    party_id: PartyId,
    protocol_signer: ProtocolSigner,
}

impl SingleSigner {
    pub(super) fn new(party_id: PartyId, protocol_signer: ProtocolSigner) -> Self {
        Self {
            party_id,
            protocol_signer,
        }
    }

    /// Issue a single signature for the given message.
    ///
    /// If no lottery are won None will be returned.
    pub fn sign(&self, message: &ProtocolMessage) -> StdResult<Option<SingleSignatures>> {
        match self.protocol_signer.sign(message.compute_hash().as_bytes()) {
            Some(signature) => {
                let won_indexes = signature.indexes.clone();

                Ok(Some(SingleSignatures::new(
                    self.party_id.to_owned(),
                    signature.into(),
                    won_indexes,
                )))
            }
            None => Ok(None),
        }
    }

    /// Return the partyId associated with this Signer.
    pub fn get_party_id(&self) -> PartyId {
        self.party_id.clone()
    }
}
