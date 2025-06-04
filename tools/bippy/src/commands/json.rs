// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (c) 2025 - Sasha Levin <sashal@kernel.org>

use anyhow::Result;
use crate::models::DyadEntry;
use crate::providers::{ProviderFactory, VulnerabilityRecordParams};

/// Parameters for generating a JSON vulnerability record
pub struct VulnRecordParams<'a> {
    /// Provider type (e.g., "cve", "gsd", "euvd")
    pub provider_type: &'a str,
    /// Vulnerability identifier
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

/// Generate a JSON for the vulnerability record
pub fn generate_json(params: &VulnRecordParams) -> Result<String> {
    let provider = ProviderFactory::create(params.provider_type)?;
    let vuln_params = VulnerabilityRecordParams {
        vuln_id: params.vuln_id,
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
    provider.generate_json(&vuln_params)
}
