//! API Version provider service
include!(concat!(env!("OUT_DIR"), "/open_api.rs"));
use anyhow::anyhow;
use anyhow::Context;
use semver::{Version, VersionReq};
use std::collections::HashMap;
use std::sync::Arc;

use crate::common::era::EraChecker;
use crate::common::StdResult;

/// API Version provider
#[derive(Clone)]
pub struct APIVersionProvider {
    era_checker: Arc<EraChecker>,
    open_api_versions: HashMap<OpenAPIFileName, OpenAPIVersionRaw>,
}

impl APIVersionProvider {
    /// Version provider factory
    pub fn new(era_checker: Arc<EraChecker>) -> Self {
        Self {
            era_checker,
            open_api_versions: get_open_api_versions_mapping(),
        }
    }

    /// Compute the current api version
    pub fn compute_current_version(&self) -> StdResult<Version> {
        let current_era = self.era_checker.current_era();
        let open_api_spec_file_name_default = "openapi.yaml";
        let open_api_spec_file_name_era = &format!("openapi-{current_era}.yaml");
        let open_api_version_raw = self
            .open_api_versions
            .get(open_api_spec_file_name_era)
            .unwrap_or(
                self.open_api_versions
                    .get(open_api_spec_file_name_default)
                    .ok_or_else(|| anyhow!("Missing default API version"))?,
            );

        Version::parse(open_api_version_raw)
            .map_err(|e| anyhow!(e))
            .with_context(|| format!("Cannot parse Semver from: '{open_api_version_raw:?}'"))
    }

    /// Compute the current api version requirement
    pub fn compute_current_version_requirement(&self) -> StdResult<VersionReq> {
        let version = &self.compute_current_version()?;
        let version_req = if version.major > 0 {
            format!("={}", version.major)
        } else {
            format!("={}.{}", version.major, version.minor)
        };

        Ok(VersionReq::parse(&version_req)?)
    }

    /// Compute all the sorted list of all versions
    pub fn compute_all_versions_sorted() -> StdResult<Vec<Version>> {
        let mut versions = Vec::new();
        for version_raw in get_open_api_versions_mapping().into_values() {
            versions.push(Version::parse(&version_raw)?)
        }
        versions.sort();
        Ok(versions)
    }

    /// Update open api versions. Test only
    pub fn update_open_api_versions(
        &mut self,
        open_api_versions: HashMap<OpenAPIFileName, OpenAPIVersionRaw>,
    ) {
        self.open_api_versions = open_api_versions;
    }
}

#[cfg(test)]
mod test {
    use std::{collections::HashMap, sync::Arc};

    use crate::common::{
        api_version::APIVersionProvider,
        entities::Epoch,
        era::{EraChecker, SupportedEra},
    };

    #[test]
    fn test_compute_current_version_default() {
        let era_checker = EraChecker::new(SupportedEra::dummy(), Epoch(1));
        let mut version_provider = APIVersionProvider::new(Arc::new(era_checker));
        let mut open_api_versions = HashMap::new();
        open_api_versions.insert("openapi.yaml".to_string(), "1.2.3".to_string());
        version_provider.update_open_api_versions(open_api_versions);
        let api_version_provider = Arc::new(version_provider);

        assert_eq!(
            "1.2.3".to_string(),
            api_version_provider
                .compute_current_version()
                .unwrap()
                .to_string()
        )
    }

    #[test]
    fn test_compute_current_version_era_specific() {
        let era_checker = EraChecker::new(SupportedEra::dummy(), Epoch(1));
        let mut version_provider = APIVersionProvider::new(Arc::new(era_checker));
        let mut open_api_versions = HashMap::new();
        open_api_versions.insert("openapi.yaml".to_string(), "1.2.3".to_string());
        open_api_versions.insert(
            format!("openapi-{}.yaml", SupportedEra::dummy()),
            "2.1.0".to_string(),
        );
        version_provider.update_open_api_versions(open_api_versions);
        let api_version_provider = Arc::new(version_provider);

        assert_eq!(
            "2.1.0".to_string(),
            api_version_provider
                .compute_current_version()
                .unwrap()
                .to_string()
        )
    }

    #[test]
    fn test_compute_current_version_requirement_beta() {
        let era_checker = EraChecker::new(SupportedEra::dummy(), Epoch(1));
        let mut version_provider = APIVersionProvider::new(Arc::new(era_checker));
        let mut open_api_versions = HashMap::new();
        open_api_versions.insert("openapi.yaml".to_string(), "0.2.3".to_string());
        version_provider.update_open_api_versions(open_api_versions);
        let api_version_provider = Arc::new(version_provider);

        assert_eq!(
            "=0.2".to_string(),
            api_version_provider
                .compute_current_version_requirement()
                .unwrap()
                .to_string()
        )
    }

    #[test]
    fn test_compute_current_version_requirement_stable() {
        let era_checker = EraChecker::new(SupportedEra::dummy(), Epoch(1));
        let mut version_provider = APIVersionProvider::new(Arc::new(era_checker));
        let mut open_api_versions = HashMap::new();
        open_api_versions.insert("openapi.yaml".to_string(), "3.2.1".to_string());
        version_provider.update_open_api_versions(open_api_versions);
        let api_version_provider = Arc::new(version_provider);

        assert_eq!(
            "=3".to_string(),
            api_version_provider
                .compute_current_version_requirement()
                .unwrap()
                .to_string()
        )
    }

    #[test]
    fn test_compute_all_versions_sorted() {
        let all_versions_sorted = APIVersionProvider::compute_all_versions_sorted()
            .expect("Computing the list of all sorted versions should not fail");

        assert!(!all_versions_sorted.is_empty());
    }
}
