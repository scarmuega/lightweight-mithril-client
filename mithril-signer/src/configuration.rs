use config::ConfigError;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use mithril_common::{entities::PartyId, CardanoNetwork};

const SQLITE_FILE: &str = "signer.sqlite3";

/// Client configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Cardano CLI tool path
    pub cardano_cli_path: PathBuf,

    /// Path of the socket used by the Cardano CLI tool
    /// to communicate with the Cardano node
    pub cardano_node_socket_path: PathBuf,

    /// Cardano Network Magic number
    /// useful for TestNet & DevNet
    pub network_magic: Option<u64>,

    /// Cardano network
    pub network: String,

    /// Aggregator endpoint
    pub aggregator_endpoint: String,

    /// Party Id
    // TODO: Field should be removed once the signer certification is fully deployed
    pub party_id: Option<PartyId>,

    /// Run Interval
    pub run_interval: u64,

    /// Directory to snapshot
    pub db_directory: PathBuf,

    /// Directory to store signer data (Stakes, Protocol initializers, ...)
    pub data_stores_directory: PathBuf,

    /// Store retention limit. If set to None, no limit will be set.
    pub store_retention_limit: Option<usize>,

    /// File path to the KES secret key of the pool
    pub kes_secret_key_path: Option<PathBuf>,

    /// File path to the operational certificate of the pool
    pub operational_certificate_path: Option<PathBuf>,

    /// Disable immutables digests cache.
    pub disable_digests_cache: bool,

    /// If set the existing immutables digests cache will be reset.
    ///
    /// Will be ignored if set in conjunction with `disable_digests_cache`.
    pub reset_digests_cache: bool,
}

impl Config {
    /// Return the CardanoNetwork value from the configuration.
    pub fn get_network(&self) -> Result<CardanoNetwork, ConfigError> {
        CardanoNetwork::from_code(self.network.clone(), self.network_magic)
            .map_err(|e| ConfigError::Message(e.to_string()))
    }

    /// Create the SQL store directory if not exist and return the path of the
    /// SQLite3 file.
    pub fn get_sqlite_file(&self) -> PathBuf {
        let store_dir = &self.data_stores_directory;

        if !store_dir.exists() {
            std::fs::create_dir_all(store_dir).unwrap();
        }

        self.data_stores_directory.join(SQLITE_FILE)
    }
}