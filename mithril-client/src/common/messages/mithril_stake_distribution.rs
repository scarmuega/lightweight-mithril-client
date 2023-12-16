use chrono::DateTime;
use chrono::Utc;
use serde::{Deserialize, Serialize};

use crate::common::entities::Epoch;
use crate::common::entities::ProtocolParameters;

use super::SignerWithStakeMessagePart;
/// Message structure of a Mithril Stake Distribution
#[derive(Clone, Debug, PartialEq, Default, Serialize, Deserialize)]
pub struct MithrilStakeDistributionMessage {
    /// Epoch at which the Mithril Stake Distribution is created
    pub epoch: Epoch,

    /// List of signers with stakes of the Mithril Stake Distribution
    #[serde(rename = "signers")]
    pub signers_with_stake: Vec<SignerWithStakeMessagePart>,

    /// Hash of the Mithril Stake Distribution (different from the AVK).
    pub hash: String,

    /// Hash of the associated certificate
    pub certificate_hash: String,

    /// DateTime of creation
    pub created_at: DateTime<Utc>,

    /// Protocol parameters used to compute AVK
    pub protocol_parameters: ProtocolParameters,
}
