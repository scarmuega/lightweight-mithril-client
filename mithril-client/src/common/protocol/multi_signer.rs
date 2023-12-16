use anyhow::{anyhow, Context};
use mithril_stm::stm::StmParameters;

use crate::common::{
    crypto_helper::{
        ProtocolAggregateVerificationKey, ProtocolAggregationError, ProtocolClerk,
        ProtocolMultiSignature,
    },
    entities::{ProtocolMessage, SingleSignatures},
    StdResult,
};

/// MultiSigner is the cryptographic engine in charge of producing multi-signatures from individual signatures
pub struct MultiSigner {
    protocol_clerk: ProtocolClerk,
    protocol_parameters: StmParameters,
}

impl MultiSigner {
    pub(super) fn new(protocol_clerk: ProtocolClerk, protocol_parameters: StmParameters) -> Self {
        Self {
            protocol_clerk,
            protocol_parameters,
        }
    }

    /// Aggregate the given single signatures into a multi-signature
    pub fn aggregate_single_signatures(
        &self,
        single_signatures: &[SingleSignatures],
        protocol_message: &ProtocolMessage,
    ) -> Result<ProtocolMultiSignature, ProtocolAggregationError> {
        let protocol_signatures: Vec<_> = single_signatures
            .iter()
            .map(|single_signature| single_signature.to_protocol_signature())
            .collect();

        self.protocol_clerk
            .aggregate(
                &protocol_signatures,
                protocol_message.compute_hash().as_bytes(),
            )
            .map(|multi_sig| multi_sig.into())
    }

    /// Compute aggregate verification key from stake distribution
    pub fn compute_aggregate_verification_key(&self) -> ProtocolAggregateVerificationKey {
        self.protocol_clerk.compute_avk().into()
    }

    /// Verify a single signature
    pub fn verify_single_signature(
        &self,
        message: &ProtocolMessage,
        single_signature: &SingleSignatures,
    ) -> StdResult<()> {
        let protocol_signature = single_signature.to_protocol_signature();

        let avk = self.compute_aggregate_verification_key();

        // If there is no reg_party, then we simply received a signature from a non-registered
        // party, and we can ignore the request.
        let (vk, stake) = self
            .protocol_clerk
            .get_reg_party(&protocol_signature.signer_index)
            .ok_or_else(|| {
                anyhow!(format!(
                    "Unregistered party: '{}'",
                    single_signature.party_id
                ))
            })?;

        protocol_signature
            .verify(
                &self.protocol_parameters,
                &vk,
                &stake,
                &avk,
                message.compute_hash().as_bytes(),
            )
            .with_context(|| {
                format!(
                    "Invalid signature for party: '{}'",
                    single_signature.party_id
                )
            })?;

        Ok(())
    }
}
