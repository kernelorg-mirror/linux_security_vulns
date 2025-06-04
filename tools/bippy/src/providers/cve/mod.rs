pub mod models;
pub mod json;
pub mod mbox;

use anyhow::Result;
use crate::providers::{VulnerabilityProvider, VulnerabilityRecordParams};

/// CVE provider implementation
pub struct CveProvider;

impl CveProvider {
    pub fn new() -> Self {
        CveProvider
    }
}

impl VulnerabilityProvider for CveProvider {
    fn generate_json(&self, params: &VulnerabilityRecordParams) -> Result<String> {
        // Get the UUID for this provider
        let uuid = match self.get_org_uuid()? {
            Some(u) => u,
            None => return Err(anyhow::anyhow!("CVE provider requires an organization UUID")),
        };

        let cve_params = json::CveRecordParams {
            uuid: &uuid,
            cve_number: params.vuln_id,
            git_sha_full: params.git_sha_full,
            commit_subject: params.commit_subject,
            user_name: params.user_name,
            user_email: params.user_email,
            dyad_entries: params.dyad_entries.clone(),
            script_name: params.script_name,
            script_version: params.script_version,
            additional_references: params.additional_references,
            commit_text: params.commit_text,
            affected_files: params.affected_files,
        };
        json::generate_json(&cve_params)
    }

    fn generate_mbox(&self, params: &VulnerabilityRecordParams) -> Result<String> {
        let mbox_params = mbox::MboxParams {
            cve_number: params.vuln_id,
            git_sha_full: params.git_sha_full,
            commit_subject: params.commit_subject,
            user_name: params.user_name,
            user_email: params.user_email,
            dyad_entries: &params.dyad_entries,
            script_name: params.script_name,
            script_version: params.script_version,
            additional_references: params.additional_references,
            commit_text: params.commit_text,
            affected_files: params.affected_files,
        };
        Ok(mbox::generate_mbox(&mbox_params))
    }

    fn name(&self) -> &'static str {
        "CVE"
    }

    fn user_env_var(&self) -> &'static str {
        "CVE_USER"
    }

    fn validate_id(&self, id: &str) -> Result<()> {
        if id.starts_with("CVE-") && id.len() > 4 {
            Ok(())
        } else {
            Err(anyhow::anyhow!("Invalid CVE ID format: {}. Expected format: CVE-YYYY-NNNN", id))
        }
    }

    fn get_org_uuid(&self) -> Result<Option<String>> {
        use crate::utils::file::read_uuid;
        use anyhow::Context;

        // Get vulns directory using vuln_utils
        let vulns_dir = vuln_utils::find_vulns_dir()
            .with_context(|| "Failed to find vulns directory")?;

        // Get the script directory from vulns directory
        let script_dir = vulns_dir.join("scripts");
        if !script_dir.exists() {
            return Err(anyhow::anyhow!(
                "Scripts directory not found at {}",
                script_dir.display()
            ));
        }

        // Read the UUID from the CVE-specific linux.uuid file
        let uuid = read_uuid(&script_dir, "linux.uuid")
            .with_context(|| "Failed to read UUID")?;

        Ok(Some(uuid))
    }
}
