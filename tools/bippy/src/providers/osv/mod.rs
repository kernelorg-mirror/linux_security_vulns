pub mod json;
pub mod models;

use crate::providers::{VulnerabilityProvider, VulnerabilityRecordParams};
use anyhow::Result;

/// Osv provider implementation
pub struct OsvProvider;

impl OsvProvider {
    pub fn new() -> Self {
        OsvProvider
    }
}

impl VulnerabilityProvider for OsvProvider {
    fn generate_json(&self, params: &VulnerabilityRecordParams) -> Result<String> {
        let osv_params = json::OsvRecordParams {
            id_number: params.vuln_id,
            git_fix_commit: params.git_sha_full,
            commit_subject: params.commit_subject,
            dyad_entries: params.dyad_entries.clone(),
            script_name: params.script_name,
            script_version: params.script_version,
            additional_references: params.additional_references,
            commit_text: params.commit_text,
            affected_files: params.affected_files,
        };
        json::generate_json(&osv_params)
    }

    fn generate_mbox(&self, _params: &VulnerabilityRecordParams) -> Result<String> {
        // Generate a simple plain text mbox format
        let mbox = "Not Supported".to_string();

        Ok(mbox)
    }

    fn name(&self) -> &'static str {
        "OSV"
    }

    fn user_env_var(&self) -> &'static str {
        "OSV_USER"
    }

    fn validate_id(&self, id: &str) -> Result<()> {
        if id.starts_with("CVE-") && id.len() > 4 {
            Ok(())
        } else {
            Err(anyhow::anyhow!(
                "Invalid CVE ID format: {}. Expected format: CVE-YYYY-NNNN",
                id
            ))
        }
    }
}
