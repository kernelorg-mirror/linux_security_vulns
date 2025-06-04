pub mod common;
pub mod cve;

pub use common::{CpeMatch, CpeNodes, VersionRange};

use anyhow::{Result, anyhow};
use crate::models::DyadEntry;

/// Common parameters for vulnerability record generation
pub struct VulnerabilityRecordParams<'a> {
    /// Vulnerability identifier (e.g., "CVE-2023-12345", "GSD-2023-12345")
    pub vuln_id: &'a str,
    /// Full Git SHA of the commit that fixes the vulnerability
    pub git_sha_full: &'a str,
    /// Subject line of the commit
    pub commit_subject: &'a str,
    /// Name of the user creating the record
    pub user_name: &'a str,
    /// Email of the user creating the record
    pub user_email: &'a str,
    /// Dyad entries containing vulnerability and fix information
    pub dyad_entries: Vec<DyadEntry>,
    /// Name of the script generating the record
    pub script_name: &'a str,
    /// Version of the script generating the record
    pub script_version: &'a str,
    /// Additional reference URLs
    pub additional_references: &'a [String],
    /// Full commit text/description
    pub commit_text: &'a str,
    /// List of affected files
    pub affected_files: &'a Vec<String>,
}

/// Trait for vulnerability providers (CVE, GSD, EUVD, etc.)
#[allow(dead_code)]
pub trait VulnerabilityProvider {
    /// Generate JSON record for the vulnerability
    fn generate_json(&self, params: &VulnerabilityRecordParams) -> Result<String>;

    /// Generate mbox announcement for the vulnerability
    fn generate_mbox(&self, params: &VulnerabilityRecordParams) -> Result<String>;

    /// Get the provider name
    fn name(&self) -> &'static str;

    /// Get the environment variable name for user configuration
    fn user_env_var(&self) -> &'static str;

    /// Validate the vulnerability ID format
    fn validate_id(&self, id: &str) -> Result<()>;

    /// Get the organization UUID if required by the provider
    /// Returns None if the provider doesn't use UUIDs
    fn get_org_uuid(&self) -> Result<Option<String>> {
        Ok(None)
    }
}

/// Factory for creating vulnerability providers
pub struct ProviderFactory;

impl ProviderFactory {
    /// Create a provider by name
    pub fn create(provider_type: &str) -> Result<Box<dyn VulnerabilityProvider>> {
        match provider_type.to_lowercase().as_str() {
            "cve" => Ok(Box::new(cve::CveProvider::new())),
            _ => Err(anyhow!("Unknown provider type: {}", provider_type)),
        }
    }

    /// Get list of available providers
    #[allow(dead_code)]
    pub fn available_providers() -> Vec<&'static str> {
        vec!["cve"]
    }
}
