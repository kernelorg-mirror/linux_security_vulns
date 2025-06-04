// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (c) 2025 - Sasha Levin <sashal@kernel.org>

use anyhow::Result;
use serde::Serialize;
use serde_json::ser::{PrettyFormatter, Serializer};
use std::collections::HashSet;

use super::models::{
    AffectedProduct, CnaData, Containers, CpeApplicability, CveMetadata, CveRecord,
    Description, Generator, ProviderMetadata, Reference,
};
use crate::providers::CpeNodes;
use crate::models::DyadEntry;
use crate::utils::{
    determine_default_status, generate_cpe_ranges, generate_git_ranges, generate_version_ranges,
};

/// Parameters for generating a JSON CVE record
pub struct CveRecordParams<'a> {
    /// Organization UUID
    pub uuid: &'a str,
    /// CVE identifier (e.g., "CVE-2023-12345")
    pub cve_number: &'a str,
    /// Full Git SHA of the commit that fixes the vulnerability
    pub git_sha_full: &'a str,
    /// Subject line of the commit
    pub commit_subject: &'a str,
    /// Name of the user creating the CVE
    pub user_name: &'a str,
    /// Email of the user creating the CVE
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


/// Prepare dyad entries and affected files
fn prepare_vulnerability_data(
    git_sha_full: &str,
    in_dyad_entries: &[DyadEntry],
) -> Result<Vec<DyadEntry>> {
    // Clone dyad entries since we might need to modify them
    let mut dyad_entries = in_dyad_entries.to_vec();

    // If no entries were created, use the fix commit as a fallback
    if dyad_entries.is_empty() {
        // Create a dummy entry using the fix commit
        if let Ok(entry) = DyadEntry::new(&format!("0:0:0:{git_sha_full}")) {
            dyad_entries.push(entry);
        }
    }

    Ok(dyad_entries)
}

/// Create affected products (kernel and git)
fn create_affected_products(
    dyad_entries: &[DyadEntry],
    affected_files: Vec<String>,
) -> (AffectedProduct, AffectedProduct, Vec<CpeNodes>) {
    // Determine default status
    let default_status = determine_default_status(dyad_entries);

    // Generate version ranges for kernel product
    let kernel_versions = generate_version_ranges(dyad_entries, default_status);
    let kernel_product = AffectedProduct {
        product: "Linux".to_string(),
        vendor: "Linux".to_string(),
        default_status: default_status.to_string(),
        repo: "https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git".to_string(),
        program_files: affected_files.clone(),
        versions: kernel_versions,
    };

    // Generate git ranges for git product
    let git_versions = generate_git_ranges(dyad_entries);
    let git_product = AffectedProduct {
        product: "Linux".to_string(),
        vendor: "Linux".to_string(),
        default_status: "unaffected".to_string(),
        repo: "https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git".to_string(),
        program_files: affected_files,
        versions: git_versions,
    };

    // Generate CPE ranges
    let cpe_nodes = generate_cpe_ranges(dyad_entries);

    (kernel_product, git_product, cpe_nodes)
}

/// Generate references from dyad entries and additional references
fn generate_references(
    dyad_entries: &[DyadEntry],
    additional_references: &[String],
    git_sha_full: &str,
) -> Vec<Reference> {
    let mut references = Vec::new();
    let mut seen_refs: HashSet<String> = HashSet::new();

    // Add references for all entries
    for entry in dyad_entries {
        // Add fixed commit reference if available
        if !entry.fixed.is_empty() {
            let url = format!("https://git.kernel.org/stable/c/{}", entry.fixed.git_id());
            if !seen_refs.contains(&url) {
                seen_refs.insert(url.clone());
                references.push(Reference { url });
            }
        }
    }

    // Add any additional references from the reference file
    for url in additional_references {
        if !seen_refs.contains(url) {
            seen_refs.insert(url.clone());
            references.push(Reference { url: url.clone() });
        }
    }

    // If no references were found, add the main fix commit
    if references.is_empty() {
        let main_fix_url = format!("https://git.kernel.org/stable/c/{git_sha_full}");
        references.push(Reference { url: main_fix_url });
    }

    references
}

/// Process commit description text and handle truncation
fn process_description(commit_text: &str) -> String {
    // Truncate description to 3982 characters (CVE backend limit) if needed
    let max_length = 3982; // CVE backend limit

    if commit_text.len() <= max_length {
        // If already under the limit, just ensure no trailing newline
        return commit_text.trim_end().to_string();
    }

    // Get the truncated text limited to max_length
    let truncated = &commit_text[..max_length];

    // Special case: if only over by a trailing newline, just trim it
    if commit_text.len() == max_length + 1 && commit_text.ends_with('\n') {
        truncated.to_string()
    } else {
        // Add truncation marker, with proper newline handling
        let separator = if truncated.ends_with('\n') { "" } else { "\n" };
        format!("{truncated}{separator}---truncated---")
    }
}

/// Parameters for creating a CVE record
struct CveRecordCreationParams<'a> {
    uuid: String,
    cve_number: &'a str,
    commit_subject: &'a str,
    user_email: &'a str,
    script_name: &'a str,
    script_version: &'a str,
    truncated_description: String,
    kernel_product: AffectedProduct,
    git_product: AffectedProduct,
    cpe_nodes: Vec<CpeNodes>,
    references: Vec<Reference>,
}

/// Create the CVE record structure
fn create_cve_record(params: CveRecordCreationParams) -> CveRecord {
    CveRecord {
        containers: Containers {
            cna: CnaData {
                provider_metadata: ProviderMetadata {
                    org_id: params.uuid.clone(),
                },
                descriptions: vec![Description {
                    lang: "en".to_string(),
                    value: params.truncated_description,
                }],
                affected: vec![params.git_product, params.kernel_product],
                cpe_applicability: vec![CpeApplicability {
                    nodes: params.cpe_nodes,
                }],
                references: params.references,
                title: params.commit_subject.to_string(),
                x_generator: Generator {
                    engine: format!("{}-{}", params.script_name, params.script_version),
                },
            },
        },
        cve_metadata: CveMetadata {
            assigner_org_id: params.uuid,
            cve_id: params.cve_number.to_string(),
            requester_user_id: params.user_email.to_string(),
            serial: "1".to_string(),
            state: "PUBLISHED".to_string(),
        },
        data_type: "CVE_RECORD".to_string(),
        data_version: "5.0".to_string(),
    }
}

/// Serialize the CVE record to JSON
fn serialize_cve_record(cve_record: &CveRecord) -> Result<String> {
    // Use a custom formatter with 3-space indentation
    let formatter = PrettyFormatter::with_indent(b"   ");
    let mut output = Vec::new();
    let mut serializer = Serializer::with_formatter(&mut output, formatter);

    cve_record
        .serialize(&mut serializer)
        .map_err(|e| anyhow::anyhow!("Error serializing JSON: {e}"))?;

    let json_string = String::from_utf8(output)
        .map_err(|e| anyhow::anyhow!("Error converting JSON to string: {e}"))?;

    // Ensure the JSON output ends with a newline
    if json_string.ends_with('\n') {
        Ok(json_string)
    } else {
        Ok(json_string + "\n")
    }
}

/// Generate a JSON for the CVE
pub fn generate_json(params: &CveRecordParams) -> Result<String> {
    let CveRecordParams {
        uuid,
        cve_number,
        git_sha_full,
        commit_subject,
        user_name: _user_name, // Not used in this function
        user_email,
        dyad_entries: in_dyad_entries,
        script_name,
        script_version,
        additional_references,
        commit_text,
        affected_files,
    } = params;

    // Prepare dyad entries
    let dyad_entries = prepare_vulnerability_data(git_sha_full, in_dyad_entries)?;

    // Create affected products
    let (kernel_product, git_product, cpe_nodes) =
        create_affected_products(&dyad_entries, (*affected_files).clone());

    // Generate references
    let references = generate_references(&dyad_entries, additional_references, git_sha_full);

    // Process description
    let truncated_description = process_description(commit_text);

    // Create CVE record
    let cve_record = create_cve_record(CveRecordCreationParams {
        uuid: uuid.to_string(),
        cve_number,
        commit_subject,
        user_email,
        script_name,
        script_version,
        truncated_description,
        kernel_product,
        git_product,
        cpe_nodes,
        references,
    });

    // Serialize CVE record to JSON
    serialize_cve_record(&cve_record)
}
