use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, fmt::Display};

/// The key of a ProtocolMessage
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum ProtocolMessagePartKey {
    /// The ProtocolMessage part key associated to the Snapshot Digest
    #[serde(rename = "snapshot_digest")]
    SnapshotDigest,

    /// The ProtocolMessage part key associated to the Next epoch aggregate verification key
    /// The AVK that will be allowed to be used to sign during the next epoch
    /// aka AVK(n-1)
    #[serde(rename = "next_aggregate_verification_key")]
    NextAggregateVerificationKey,
}

impl Display for ProtocolMessagePartKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            Self::SnapshotDigest => write!(f, "snapshot_digest"),
            Self::NextAggregateVerificationKey => write!(f, "next_aggregate_verification_key"),
        }
    }
}

/// The value of a ProtocolMessage
pub type ProtocolMessagePartValue = String;

/// ProtocolMessage represents a message that is signed (or verified) by the Mithril protocol
#[derive(Clone, Debug, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ProtocolMessage {
    /// Map of the messages combined into the digest
    /// aka MSG(p,n)
    pub message_parts: BTreeMap<ProtocolMessagePartKey, ProtocolMessagePartValue>,
}

impl ProtocolMessage {
    /// ProtocolMessage factory
    pub fn new() -> ProtocolMessage {
        ProtocolMessage {
            message_parts: BTreeMap::new(),
        }
    }

    /// Set the message part associated with a key
    /// Returns previously set value if it exists
    pub fn set_message_part(
        &mut self,
        key: ProtocolMessagePartKey,
        value: ProtocolMessagePartValue,
    ) -> Option<ProtocolMessagePartValue> {
        self.message_parts.insert(key, value)
    }

    /// Get the message part associated with a key
    pub fn get_message_part(
        &self,
        key: &ProtocolMessagePartKey,
    ) -> Option<&ProtocolMessagePartValue> {
        self.message_parts.get(key)
    }

    /// Computes the hash of the protocol message
    pub fn compute_hash(&self) -> String {
        let mut hasher = Sha256::new();
        self.message_parts.iter().for_each(|(k, v)| {
            hasher.update(k.to_string().as_bytes());
            hasher.update(v.as_bytes());
        });
        hex::encode(hasher.finalize())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_protocol_message_compute_hash() {
        let hash_expected = "71dee1e558cd647cdbc219a24b766940f568e7e8287c30a8292209ef11666e03";

        let mut protocol_message = ProtocolMessage::new();
        protocol_message.set_message_part(
            ProtocolMessagePartKey::SnapshotDigest,
            "snapshot-digest-123".to_string(),
        );
        protocol_message.set_message_part(
            ProtocolMessagePartKey::NextAggregateVerificationKey,
            "next-avk-123".to_string(),
        );
        assert_eq!(hash_expected, protocol_message.compute_hash());

        let mut protocol_message_modified = protocol_message.clone();
        protocol_message_modified.set_message_part(
            ProtocolMessagePartKey::NextAggregateVerificationKey,
            "next-avk-456".to_string(),
        );
        assert_ne!(hash_expected, protocol_message_modified.compute_hash());

        let mut protocol_message_modified = protocol_message.clone();
        protocol_message_modified.set_message_part(
            ProtocolMessagePartKey::SnapshotDigest,
            "snapshot-digest-456".to_string(),
        );
        assert_ne!(hash_expected, protocol_message_modified.compute_hash());
    }
}
