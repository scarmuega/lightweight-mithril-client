use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::common::entities::{Beacon, CompressionAlgorithm, Epoch};

/// Message structure of a snapshot
#[derive(Clone, Debug, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct SnapshotMessage {
    /// Digest that is signed by the signer participants
    pub digest: String,

    /// Mithril beacon on the Cardano chain
    pub beacon: Beacon,

    /// Hash of the associated certificate
    pub certificate_hash: String,

    /// Size of the snapshot file in Bytes
    pub size: u64,

    /// Date and time at which the snapshot was created
    pub created_at: DateTime<Utc>,

    /// Locations where the binary content of the snapshot can be retrieved
    pub locations: Vec<String>,

    /// Compression algorithm of the snapshot archive
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compression_algorithm: Option<CompressionAlgorithm>,

    /// Cardano node version
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cardano_node_version: Option<String>,
}

impl SnapshotMessage {
    /// Return a dummy test entity (test-only).
    pub fn dummy() -> Self {
        Self {
            digest: "0b9f5ad7f33cc523775c82249294eb8a1541d54f08eb3107cafc5638403ec7c6".to_string(),
            beacon: Beacon {
                network: "preview".to_string(),
                epoch: Epoch(86),
                immutable_file_number: 1728,
            },
            certificate_hash: "d5daf6c03ace4a9c074e951844075b9b373bafc4e039160e3e2af01823e9abfb"
                .to_string(),
            size: 807803196,
            created_at: DateTime::parse_from_rfc3339("2023-01-19T13:43:05.618857482Z")
                .unwrap()
                .with_timezone(&Utc),
            locations: vec!["https://host/certificate.tar.gz".to_string()],
            compression_algorithm: Some(CompressionAlgorithm::Gzip),
            cardano_node_version: Some("0.0.1".to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn golden_message_v1() -> SnapshotMessage {
        SnapshotMessage {
            digest: "0b9f5ad7f33cc523775c82249294eb8a1541d54f08eb3107cafc5638403ec7c6".to_string(),
            beacon: Beacon {
                network: "preview".to_string(),
                epoch: Epoch(86),
                immutable_file_number: 1728,
            },
            certificate_hash: "d5daf6c03ace4a9c074e951844075b9b373bafc4e039160e3e2af01823e9abfb"
                .to_string(),
            size: 807803196,
            created_at: DateTime::parse_from_rfc3339("2023-01-19T13:43:05.618857482Z")
                .unwrap()
                .with_timezone(&Utc),
            locations: vec!["https://host/certificate.tar.gz".to_string()],
            compression_algorithm: None,
            cardano_node_version: None,
        }
    }

    fn golden_message_v2() -> SnapshotMessage {
        SnapshotMessage {
            digest: "0b9f5ad7f33cc523775c82249294eb8a1541d54f08eb3107cafc5638403ec7c6".to_string(),
            beacon: Beacon {
                network: "preview".to_string(),
                epoch: Epoch(86),
                immutable_file_number: 1728,
            },
            certificate_hash: "d5daf6c03ace4a9c074e951844075b9b373bafc4e039160e3e2af01823e9abfb"
                .to_string(),
            size: 807803196,
            created_at: DateTime::parse_from_rfc3339("2023-01-19T13:43:05.618857482Z")
                .unwrap()
                .with_timezone(&Utc),
            locations: vec!["https://host/certificate.tar.gz".to_string()],
            compression_algorithm: Some(CompressionAlgorithm::Gzip),
            cardano_node_version: Some("0.0.1".to_string()),
        }
    }

    // Test the retro compatibility with possible future upgrades.
    #[test]
    fn test_v1() {
        let json = r#"{
"digest": "0b9f5ad7f33cc523775c82249294eb8a1541d54f08eb3107cafc5638403ec7c6",
"beacon": {
  "network": "preview",
  "epoch": 86,
  "immutable_file_number": 1728
},
"certificate_hash": "d5daf6c03ace4a9c074e951844075b9b373bafc4e039160e3e2af01823e9abfb",
"size": 807803196,
"created_at": "2023-01-19T13:43:05.618857482Z",
"locations": [
  "https://host/certificate.tar.gz"
]
}"#;
        let message: SnapshotMessage = serde_json::from_str(json).expect(
            "This JSON is expected to be succesfully parsed into a SnapshotMessage instance.",
        );

        assert_eq!(golden_message_v1(), message);
    }

    #[test]
    fn test_v2() {
        let json = r#"{
"digest": "0b9f5ad7f33cc523775c82249294eb8a1541d54f08eb3107cafc5638403ec7c6",
"beacon": {
  "network": "preview",
  "epoch": 86,
  "immutable_file_number": 1728
},
"certificate_hash": "d5daf6c03ace4a9c074e951844075b9b373bafc4e039160e3e2af01823e9abfb",
"size": 807803196,
"created_at": "2023-01-19T13:43:05.618857482Z",
"locations": [
  "https://host/certificate.tar.gz"
],
"compression_algorithm": "gzip",
"cardano_node_version": "0.0.1"
}"#;
        let message: SnapshotMessage = serde_json::from_str(json).expect(
            "This JSON is expected to be succesfully parsed into a SnapshotMessage instance.",
        );

        assert_eq!(golden_message_v2(), message);
    }
}
