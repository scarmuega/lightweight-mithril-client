use anyhow::Context;
use rand_chacha::ChaCha20Rng;
use rand_core::{CryptoRng, RngCore, SeedableRng};
use std::path::Path;
use thiserror::Error;

use crate::common::{
    crypto_helper::{
        ProtocolAggregateVerificationKey, ProtocolClerk, ProtocolClosedKeyRegistration,
        ProtocolInitializer, ProtocolKeyRegistration, ProtocolStakeDistribution,
    },
    entities::{PartyId, ProtocolParameters, SignerWithStake},
    protocol::MultiSigner,
    StdResult,
};

use super::SingleSigner;

/// Allow to build Single Or Multi signers to generate a single signature or aggregate them
#[derive(Debug)]
pub struct SignerBuilder {
    protocol_parameters: ProtocolParameters,
    closed_key_registration: ProtocolClosedKeyRegistration,
}

/// [SignerBuilder] specific errors
#[derive(Debug, Error)]
pub enum SignerBuilderError {
    /// Error raised when the list of signers given to the builder is empty
    #[error("The list of signers must not be empty to create a signer builder.")]
    EmptySigners,
}

impl SignerBuilder {
    /// [SignerBuilder] constructor.
    pub fn new(
        registered_signers: &[SignerWithStake],
        protocol_parameters: &ProtocolParameters,
    ) -> StdResult<Self> {
        if registered_signers.is_empty() {
            return Err(SignerBuilderError::EmptySigners.into());
        }

        let stake_distribution = registered_signers
            .iter()
            .map(|s| s.into())
            .collect::<ProtocolStakeDistribution>();
        let mut key_registration = ProtocolKeyRegistration::init(&stake_distribution);

        for signer in registered_signers {
            key_registration
                .register(
                    Some(signer.party_id.to_owned()),
                    signer.operational_certificate.clone(),
                    signer.verification_key_signature,
                    signer.kes_period,
                    signer.verification_key,
                )
                .with_context(|| {
                    format!("Registration failed for signer: '{}'", signer.party_id)
                })?;
        }

        let closed_registration = key_registration.close();

        Ok(Self {
            protocol_parameters: protocol_parameters.clone(),
            closed_key_registration: closed_registration,
        })
    }

    /// Build a [MultiSigner] based on the registered parties
    pub fn build_multi_signer(&self) -> MultiSigner {
        let stm_parameters = self.protocol_parameters.clone().into();
        let clerk =
            ProtocolClerk::from_registration(&stm_parameters, &self.closed_key_registration);

        MultiSigner::new(clerk, stm_parameters)
    }

    /// Compute aggregate verification key from stake distribution
    pub fn compute_aggregate_verification_key(&self) -> ProtocolAggregateVerificationKey {
        let stm_parameters = self.protocol_parameters.clone().into();
        let clerk =
            ProtocolClerk::from_registration(&stm_parameters, &self.closed_key_registration);

        clerk.compute_avk().into()
    }

    fn build_single_signer_with_rng<R: RngCore + CryptoRng>(
        &self,
        signer_with_stake: SignerWithStake,
        kes_secret_key_path: Option<&Path>,
        rng: &mut R,
    ) -> StdResult<(SingleSigner, ProtocolInitializer)> {
        let protocol_initializer = ProtocolInitializer::setup(
            self.protocol_parameters.clone().into(),
            kes_secret_key_path,
            signer_with_stake.kes_period,
            signer_with_stake.stake,
            rng,
        )
        .with_context(|| {
            format!(
                "Could not create a protocol initializer for party: '{}'",
                signer_with_stake.party_id
            )
        })?;

        let protocol_signer = protocol_initializer
            .clone()
            .new_signer(self.closed_key_registration.clone())
            .with_context(|| {
                format!(
                    "Could not create a protocol signer for party: '{}'",
                    signer_with_stake.party_id
                )
            })?;

        Ok((
            SingleSigner::new(signer_with_stake.party_id, protocol_signer),
            protocol_initializer,
        ))
    }

    /// Build non deterministic [SingleSigner] and [ProtocolInitializer] based on the registered parties.
    #[cfg(feature = "random")]
    #[cfg_attr(docsrs, doc(cfg(feature = "random")))]
    pub fn build_single_signer(
        &self,
        signer_with_stake: SignerWithStake,
        kes_secret_key_path: Option<&Path>,
    ) -> StdResult<(SingleSigner, ProtocolInitializer)> {
        self.build_single_signer_with_rng(
            signer_with_stake,
            kes_secret_key_path,
            &mut rand_core::OsRng,
        )
    }

    /// Build deterministic [SingleSigner] and [ProtocolInitializer] based on the registered parties.
    ///
    /// Use for **TEST ONLY**.
    pub fn build_test_single_signer(
        &self,
        signer_with_stake: SignerWithStake,
        kes_secret_key_path: Option<&Path>,
    ) -> StdResult<(SingleSigner, ProtocolInitializer)> {
        let protocol_initializer_seed: [u8; 32] = signer_with_stake.party_id.as_bytes()[..32]
            .try_into()
            .unwrap();

        self.build_single_signer_with_rng(
            signer_with_stake,
            kes_secret_key_path,
            &mut ChaCha20Rng::from_seed(protocol_initializer_seed),
        )
    }

    /// Restore a [SingleSigner] based on the registered parties and the given
    /// protocol_initializer.
    ///
    /// This is useful since each protocol initializer holds a unique secret key
    /// that corresponds to a registration key sent to an aggregator.
    ///
    /// The actual signing of message is done at a later epoch.
    ///
    /// The [SignerBuilder] used must be tied to the key registration, stake distribution
    /// and protocol parameters of the epoch during which the given protocol initializer
    /// was created.
    pub fn restore_signer_from_initializer(
        &self,
        party_id: PartyId,
        protocol_initializer: ProtocolInitializer,
    ) -> StdResult<SingleSigner> {
        let single_signer = protocol_initializer
            .new_signer(self.closed_key_registration.clone())
            .with_context(|| {
                "Could not create a single signer from protocol initializer".to_string()
            })?;

        Ok(SingleSigner::new(party_id, single_signer))
    }
}
