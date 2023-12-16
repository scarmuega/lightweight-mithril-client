/// Mithril result type, an alias of [anyhow::Result]
pub type MithrilResult<T> = anyhow::Result<T>;

/// Mithril error type, an alias of [anyhow::Error]
pub type MithrilError = anyhow::Error;

/// A Mithril snapshot of a Cardano Node database.
///
pub use crate::common::messages::SnapshotMessage as Snapshot;

/// List item of Mithril snapshots
///
pub use crate::common::messages::SnapshotListItemMessage as SnapshotListItem;

/// A Mithril stake distribution.
///
pub use crate::common::messages::MithrilStakeDistributionMessage as MithrilStakeDistribution;

/// List item of Mithril stake distributions.
///
pub use crate::common::messages::MithrilStakeDistributionListItemMessage as MithrilStakeDistributionListItem;

/// A Mithril certificate.
///
pub use crate::common::messages::CertificateMessage as MithrilCertificate;

pub use crate::common::messages::CertificateMetadataMessagePart as MithrilCertificateMetadata;

/// List item of Mithril certificates
///
pub use crate::common::messages::CertificateListItemMessage as MithrilCertificateListItem;

pub use crate::common::messages::CertificateListItemMessageMetadata as MithrilCertificateListItemMetadata;

/// An individual signer of a [Mithril certificate][MithrilCertificate]
///
pub use crate::common::messages::SignerWithStakeMessagePart as MithrilSigner;
