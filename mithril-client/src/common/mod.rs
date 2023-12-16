pub mod api_version;
pub mod certificate_chain;
pub mod crypto_helper;
pub mod digesters;
pub mod entities;
pub mod era;
pub mod messages;
pub mod protocol;
pub mod signable_builder;

/// Mithril API protocol version header name
pub const MITHRIL_API_VERSION_HEADER: &str = "mithril-api-version";

/// Generic error type
pub type StdError = anyhow::Error;

/// Generic result type
pub type StdResult<T> = anyhow::Result<T, StdError>;
