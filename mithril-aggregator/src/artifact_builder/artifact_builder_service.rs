use async_trait::async_trait;

use std::sync::Arc;

use mithril_common::{
    entities::{Beacon, Certificate, Epoch, SignedEntityType, Snapshot},
    signable_builder::Artifact,
    StdResult,
};

use crate::artifact_builder::ArtifactBuilder;

use super::MithrilStakeDistribution;

#[cfg(test)]
use mockall::automock;

/// ArtifactBuilder Service trait
#[cfg_attr(test, automock)]
#[async_trait]
pub trait ArtifactBuilderService: Send + Sync {
    /// Compute artifact from signed entity type
    async fn compute_artifact(
        &self,
        signed_entity_type: SignedEntityType,
        certificate: &Certificate,
    ) -> StdResult<Arc<dyn Artifact>>;
}

/// Mithril ArtifactBuilder Service
pub struct MithrilArtifactBuilderService {
    mithril_stake_distribution_artifact_builder:
        Arc<dyn ArtifactBuilder<Epoch, MithrilStakeDistribution>>,
    cardano_immutable_files_full_artifact_builder: Arc<dyn ArtifactBuilder<Beacon, Snapshot>>,
}

impl MithrilArtifactBuilderService {
    /// MithrilArtifactBuilderService factory
    #[allow(dead_code)]
    pub fn new(
        mithril_stake_distribution_artifact_builder: Arc<
            dyn ArtifactBuilder<Epoch, MithrilStakeDistribution>,
        >,
        cardano_immutable_files_full_artifact_builder: Arc<dyn ArtifactBuilder<Beacon, Snapshot>>,
    ) -> Self {
        Self {
            mithril_stake_distribution_artifact_builder,
            cardano_immutable_files_full_artifact_builder,
        }
    }
}

#[async_trait]
impl ArtifactBuilderService for MithrilArtifactBuilderService {
    #[allow(dead_code)]
    async fn compute_artifact(
        &self,
        signed_entity_type: SignedEntityType,
        certificate: &Certificate,
    ) -> StdResult<Arc<dyn Artifact>> {
        match signed_entity_type {
            SignedEntityType::MithrilStakeDistribution(epoch) => Ok(Arc::new(
                self.mithril_stake_distribution_artifact_builder
                    .compute_artifact(epoch, certificate)
                    .await?,
            )),
            SignedEntityType::CardanoImmutableFilesFull(beacon) => Ok(Arc::new(
                self.cardano_immutable_files_full_artifact_builder
                    .compute_artifact(beacon, certificate)
                    .await?,
            )),
            SignedEntityType::CardanoStakeDistribution(_) => todo!(),
        }
    }
}

#[cfg(test)]
mod tests {
    use mithril_common::{entities::Epoch, test_utils::fake_data};

    use super::*;

    use crate::artifact_builder::MockArtifactBuilder;

    #[tokio::test]
    async fn build_mithril_stake_distribution_artifact_when_given_mithril_stake_distribution_entity_type(
    ) {
        let signers_with_stake = fake_data::signers_with_stakes(5);
        let mithril_stake_distribution_expected = MithrilStakeDistribution::new(signers_with_stake);
        let mithril_stake_distribution_clone = mithril_stake_distribution_expected.clone();
        let mut mock_mithril_stake_distribution_artifact_builder =
            MockArtifactBuilder::<Epoch, MithrilStakeDistribution>::new();
        mock_mithril_stake_distribution_artifact_builder
            .expect_compute_artifact()
            .once()
            .return_once(move |_, _| Ok(mithril_stake_distribution_clone));

        let mock_cardano_immutable_files_full_artifact_builder =
            MockArtifactBuilder::<Beacon, Snapshot>::new();

        let artifact_builder_service = MithrilArtifactBuilderService::new(
            Arc::new(mock_mithril_stake_distribution_artifact_builder),
            Arc::new(mock_cardano_immutable_files_full_artifact_builder),
        );
        let certificate = Certificate::default();

        let signed_entity_type = SignedEntityType::MithrilStakeDistribution(Epoch(1));
        let artifact = artifact_builder_service
            .compute_artifact(signed_entity_type, &certificate)
            .await
            .unwrap();
        let mithril_stake_distribution_computed: MithrilStakeDistribution =
            serde_json::from_str(&serde_json::to_string(&artifact).unwrap()).unwrap();
        assert_eq!(
            serde_json::to_string(&mithril_stake_distribution_expected).unwrap(),
            serde_json::to_string(&mithril_stake_distribution_computed).unwrap()
        );
    }

    #[tokio::test]
    async fn build_snapshot_artifact_when_given_cardano_immutable_files_full_entity_type() {
        let snapshot_expected = fake_data::snapshots(1).first().unwrap().to_owned();
        let snapshot_expected_clone = snapshot_expected.clone();
        let mock_mithril_stake_distribution_artifact_builder =
            MockArtifactBuilder::<Epoch, MithrilStakeDistribution>::new();

        let mut mock_cardano_immutable_files_full_artifact_builder =
            MockArtifactBuilder::<Beacon, Snapshot>::new();
        mock_cardano_immutable_files_full_artifact_builder
            .expect_compute_artifact()
            .once()
            .return_once(move |_, _| Ok(snapshot_expected_clone));

        let artifact_builder_service = MithrilArtifactBuilderService::new(
            Arc::new(mock_mithril_stake_distribution_artifact_builder),
            Arc::new(mock_cardano_immutable_files_full_artifact_builder),
        );
        let certificate = Certificate::default();

        let signed_entity_type = SignedEntityType::CardanoImmutableFilesFull(Beacon::default());
        let artifact = artifact_builder_service
            .compute_artifact(signed_entity_type, &certificate)
            .await
            .unwrap();
        let snapshot_computed: Snapshot =
            serde_json::from_str(&serde_json::to_string(&artifact).unwrap()).unwrap();
        assert_eq!(
            serde_json::to_string(&snapshot_expected).unwrap(),
            serde_json::to_string(&snapshot_computed).unwrap()
        );
    }
}