use anyhow::anyhow;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::{str::FromStr, sync::Arc};
use thiserror::Error;

use crate::common::entities::Epoch;
use crate::common::{StdError, StdResult};

use super::SupportedEra;

/// Value object that represents a tag of Era change.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EraMarker {
    /// Era name
    pub name: String,

    /// Eventual information that advertises the Epoch of transition.
    pub epoch: Option<Epoch>,
}

impl EraMarker {
    /// instantiate a new [EraMarker].
    pub fn new(name: &str, epoch: Option<Epoch>) -> Self {
        let name = name.to_string();

        Self { name, epoch }
    }
}

/// Adapters are responsible of technically reading the information of
/// [EraMarker]s from a backend.
#[async_trait]
pub trait EraReaderAdapter: Sync + Send {
    /// Read era markers from the underlying adapter.
    async fn read(&self) -> StdResult<Vec<EraMarker>>;
}

/// This is a response from the [EraReader]. It contains [EraMarker]s read from
/// the adapter. It can try to cast the given markers to [SupportedEra]s.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EraEpochToken {
    current_epoch: Epoch,
    current_era: EraMarker,
    next_era: Option<EraMarker>,
}

impl EraEpochToken {
    /// Instanciate a new [EraMarker].
    pub fn new(current_epoch: Epoch, current_era: EraMarker, next_era: Option<EraMarker>) -> Self {
        Self {
            current_epoch,
            current_era,
            next_era,
        }
    }

    /// Try to cast the current [EraMarker] to a [SupportedEra]. If it fails,
    /// that means the current Era is not supported by this version of the
    /// software.
    pub fn get_current_supported_era(&self) -> StdResult<SupportedEra> {
        SupportedEra::from_str(&self.current_era.name)
            .map_err(|_| anyhow!(format!("Unsupported era '{}'.", &self.current_era.name)))
    }

    /// Return the [EraMarker] of the current Era.
    pub fn get_current_era_marker(&self) -> &EraMarker {
        &self.current_era
    }

    /// Return the epoch the Token has been created at
    pub fn get_current_epoch(&self) -> Epoch {
        self.current_epoch
    }

    /// Try to cast the next [EraMarker] to a [SupportedEra]. If it fails, that
    /// means the coming Era will not be supported by this version of the
    /// software. This mechanism is used to issue a warning to the user asking
    /// for upgrade.
    pub fn get_next_supported_era(&self) -> StdResult<Option<SupportedEra>> {
        match self.next_era.as_ref() {
            Some(marker) => Ok(Some(
                SupportedEra::from_str(&marker.name)
                    .map_err(|_| anyhow!(format!("Unsupported era '{}'.", &marker.name)))?,
            )),
            None => Ok(None),
        }
    }

    /// Return the [EraMarker] for the coming Era if any.
    pub fn get_next_era_marker(&self) -> Option<&EraMarker> {
        self.next_era.as_ref()
    }
}

/// The EraReader is responsible of giving the current Era and the Era to come.
/// It uses an [EraReaderAdapter] to read data from a backend.
pub struct EraReader {
    adapter: Arc<dyn EraReaderAdapter>,
}

/// Error type when [EraReader] fails to return a [EraEpochToken].
#[derive(Debug, Error)]
pub enum EraReaderError {
    /// Underlying adapter fails to return data.
    #[error("Adapter Error message: «{message}»")]
    AdapterFailure {
        /// context message
        message: String,

        /// nested underlying adapter error
        #[source]
        error: StdError,
    },

    /// Data returned from the adapter are inconsistent or incomplete.
    #[error(
        "Cannot determine the Era we are currently at epoch {epoch} using the adapter informations: {eras:?}"
    )]
    CurrentEraNotFound {
        /// Current Epoch
        epoch: Epoch,

        /// Eras given by the adapter
        eras: Vec<EraMarker>,
    },
}

impl EraReader {
    /// Instantiate the [EraReader] injecting the adapter.
    pub fn new(adapter: Arc<dyn EraReaderAdapter>) -> Self {
        Self { adapter }
    }

    /// This methods triggers the adapter to read the markers from the backend.
    /// It tries to determine the current Era and the next Era if any from the
    /// data returned from the adapter.
    pub async fn read_era_epoch_token(
        &self,
        current_epoch: Epoch,
    ) -> Result<EraEpochToken, EraReaderError> {
        let eras = self
            .adapter
            .read()
            .await
            .map_err(|e| EraReaderError::AdapterFailure {
                message: format!("Reading from EraReader adapter raised an error: '{}'.", &e),
                error: e,
            })?;

        let current_marker = eras.iter().filter(|&f| f.epoch.is_some()).fold(
            None,
            |acc: Option<&EraMarker>, marker| {
                if marker.epoch.unwrap() <= current_epoch
                    && (acc.is_none() || marker.epoch.unwrap() > acc.unwrap().epoch.unwrap())
                {
                    Some(marker)
                } else {
                    acc
                }
            },
        );
        let current_era_marker =
            current_marker.ok_or_else(|| EraReaderError::CurrentEraNotFound {
                epoch: current_epoch,
                eras: eras.clone(),
            })?;

        let next_era_marker = eras.last().filter(|&marker| marker != current_era_marker);

        Ok(EraEpochToken::new(
            current_epoch,
            current_era_marker.to_owned(),
            next_era_marker.cloned(),
        ))
    }
}
