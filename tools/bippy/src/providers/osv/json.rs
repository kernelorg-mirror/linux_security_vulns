// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (c) 2025 - Google LLC

use anyhow::Result;
use chrono::{SecondsFormat, Utc};
use serde::Serialize;
use serde_json::ser::{PrettyFormatter, Serializer};
use std::collections::{HashMap, HashSet};

use super::models::{
    Affected, Event, OsvRecord, Package, Range, RangeType, Reference, ReferenceType,
};
use crate::models::DyadEntry;

const REPO_URL: &str = "https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git";
const SCHEMA_VERSION: &str = "1.7.3";

/// Parameters for generating a JSON OSV record
pub struct OsvRecordParams<'a> {
    /// CVE identifier (e.g., "CVE-2023-12345")
    pub id_number: &'a str,
    /// Full Git SHA of the commit that fixes the vulnerability
    pub git_fix_commit: &'a str,
    /// Subject line of the commit
    pub commit_subject: &'a str,
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

// Get the git ranges in OSV format
fn dyad_to_git_ranges(dyad_entries: &[DyadEntry]) -> Vec<Range> {
    let mut grouped_by_introduced: HashMap<String, Vec<String>> = HashMap::new();

    for entry in dyad_entries {
        let introduced_id = entry.vulnerable.git_id();
        let fixed_id = entry.fixed.git_id();

        let fixes = grouped_by_introduced.entry(introduced_id).or_default();
        if fixed_id != "0" {
            fixes.push(fixed_id);
        }
    }

    let mut ranges = Vec::new();
    for entry in dyad_entries {
        let introduced = entry.vulnerable.git_id();
        if let Some(fixes) = grouped_by_introduced.remove(&introduced) {
            let mut events = vec![Event::Introduced { introduced }];

            for fixed in fixes {
                events.push(Event::Fixed { fixed });
            }

            ranges.push(Range {
                r#type: RangeType::Git,
                repo: Some(REPO_URL.to_string()),
                events,
            });
        }
    }
    ranges
}

/// Create affected field
fn create_affected(dyad_entries: &[DyadEntry], affected_files: &[String]) -> Vec<Affected> {
    let package = Package {
        name: "Kernel".to_string(),
        ecosystem: "Linux".to_string(),
        purl: None,
    };

    let git_ranges = dyad_to_git_ranges(dyad_entries);
    if git_ranges.is_empty() {
        return Vec::new();
    }

    let database_specific = if !affected_files.is_empty() {
        Some(serde_json::json!({ "affected_files": affected_files }))
    } else {
        None
    };

    vec![Affected {
        package: package.clone(),
        ranges: git_ranges,
        versions: None,
        ecosystem_specific: None,
        database_specific: database_specific.clone(),
    }]
}

/// Generate references from dyad entries and additional references
fn generate_osv_references(
    dyad_entries: &[DyadEntry],
    additional_references: &[String],
    git_fix_commit: &str,
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
                references.push(Reference {
                    r#type: ReferenceType::Fix,
                    url,
                });
            }
        }
    }

    // Add any additional references from the reference file
    for url in additional_references {
        if !seen_refs.contains(url) {
            seen_refs.insert(url.clone());
            references.push(Reference {
                r#type: ReferenceType::Web,
                url: url.clone(),
            });
        }
    }

    // If no references were found, add the main fix commit
    if references.is_empty() {
        let main_fix_url = format!("https://git.kernel.org/stable/c/{git_fix_commit}");
        references.push(Reference {
            r#type: ReferenceType::Fix,
            url: main_fix_url,
        });
    }

    references
}

/// Create the OSV record structure
fn create_osv_record(
    id_number: &str,
    commit_subject: &str,
    description: String,
    affected: Vec<Affected>,
    references: Vec<Reference>,
    database_specific: Option<serde_json::Value>,
) -> OsvRecord {
    let now = Utc::now();
    let timestamp = now.to_rfc3339_opts(SecondsFormat::Secs, true);

    OsvRecord {
        schema_version: SCHEMA_VERSION.to_string(),
        id: format!("LINUX-{}", id_number), // Prefix choice open to discussion
        modified: timestamp.clone(),
        published: Some(timestamp),
        withdrawn: None,
        summary: Some(commit_subject.to_string()),
        details: Some(description),
        affected: Some(affected),
        references: Some(references),
        severities: None,
        aliases: Some(vec![id_number.to_string()]),
        database_specific,
    }
}

/// Serialize the OSV record to JSON
fn serialize_osv_record(osv_record: &OsvRecord) -> Result<String> {
    // Use a custom formatter with 3-space indentation
    let formatter = PrettyFormatter::with_indent(b"   ");
    let mut output = Vec::new();
    let mut serializer = Serializer::with_formatter(&mut output, formatter);

    osv_record
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

/// Generate a JSON for the OSV record
pub fn generate_json(params: &OsvRecordParams) -> Result<String> {
    let OsvRecordParams {
        id_number,
        git_fix_commit,
        commit_subject,
        dyad_entries,
        additional_references,
        commit_text,
        script_name,
        script_version,
        affected_files,
    } = params;
    let default_dyad_entry;
    let mut dyad_entries = dyad_entries.as_slice();
    // Prepare dyad entries
    if dyad_entries.is_empty() {
        // Create a dummy entry using the fix commit
        if let Ok(entry) = DyadEntry::new(&format!("0:0:0:{git_fix_commit}")) {
            default_dyad_entry = vec![entry];
            dyad_entries = default_dyad_entry.as_slice();
        }
    }

    // Create affected products
    let affected = create_affected(dyad_entries, affected_files);

    // Generate references
    let references = generate_osv_references(dyad_entries, additional_references, git_fix_commit);

    // Process description
    let description = commit_text.to_string();

    let generator = format!("{}-{}", script_name, script_version);
    let database_specific = Some(serde_json::json!({ "generator": generator }));
    // Create OSV record
    let osv_record = create_osv_record(
        id_number,
        commit_subject,
        description,
        affected,
        references,
        database_specific,
    );

    // Serialize OSV record to JSON
    serialize_osv_record(&osv_record)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::DyadEntry;
    use vuln_utils::Kernel;

    #[test]
    fn test_generate_json_creates_valid_osv() {
        let affected_files = vec![];
        let additional_references = vec![];
        let params = OsvRecordParams {
            id_number: "CVE-2023-12345",
            git_fix_commit: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            commit_subject: "test: fix a bug",
            dyad_entries: Vec::new(),
            script_name: "test_script",
            script_version: "1.0",
            additional_references: &additional_references,
            commit_text: "This is the commit text.",
            affected_files: &affected_files,
        };
        let result = generate_json(&params);
        assert!(result.is_ok());
        let json_string = result.unwrap();
        let osv: OsvRecord = serde_json::from_str(&json_string).unwrap();
        assert_eq!(osv.id, "LINUX-CVE-2023-12345");
        assert_eq!(osv.summary.unwrap(), "test: fix a bug");
    }

    #[test]
    fn test_database_specific_has_generator() {
        let affected_files = vec![];
        let additional_references = vec![];
        let mut params = OsvRecordParams {
            id_number: "CVE-2023-12345",
            git_fix_commit: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            commit_subject: "test: fix a bug",
            dyad_entries: Vec::new(),
            script_name: "test_script",
            script_version: "1.0",
            additional_references: &additional_references,
            commit_text: "This is the commit text.",
            affected_files: &affected_files,
        };
        params.script_name = "my_script";
        params.script_version = "2.1";

        let result = generate_json(&params).unwrap();
        let osv: OsvRecord = serde_json::from_str(&result).unwrap();

        let database_specific = osv.database_specific.unwrap();
        let generator = database_specific
            .get("generator")
            .unwrap()
            .as_str()
            .unwrap();
        assert_eq!(generator, "my_script-2.1");
    }

    #[test]
    fn test_ecosystem_specific_has_affected_files() {
        let original_affected_files = vec![
            "kernel/cpu.c".to_string(),
            "drivers/net/ethernet/intel/ice/ice_main.c".to_string(),
        ];
        let additional_references = vec![];
        let params = OsvRecordParams {
                id_number: "CVE-2023-12345",
                git_fix_commit: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                commit_subject: "test: fix a bug",
                dyad_entries: vec![DyadEntry::new(
                    "5.15:e2f34481b24db2fd634b5edb0a5bd0e4d38cc6e9:5.15.180:571b342d4688801fc1f6a1934389dac09425dc93",
                )
                .unwrap()],
                script_name: "test_script",
                script_version: "1.0",
                additional_references: &additional_references,
                commit_text: "This is the commit text.",
                affected_files: &original_affected_files,
            };
        let result = generate_json(&params).unwrap();
        let osv: OsvRecord = serde_json::from_str(&result).unwrap();
        let affected = osv.affected.unwrap().into_iter().next().unwrap();
        let database_specific = affected.database_specific.unwrap();
        let affected_files_json = database_specific.get("affected_files").unwrap();
        let files_from_osv: Vec<String> =
            serde_json::from_value(affected_files_json.clone()).unwrap();
        assert_eq!(files_from_osv, original_affected_files);
    }

    #[test]
    fn test_generate_osv_references() {
        // Helper function to create test kernels
        fn create_test_kernel(git_id: &str) -> Kernel {
            Kernel::from_id(git_id).unwrap_or_else(|_| Kernel::empty_kernel())
        }

        // Create test dyad entries
        let fixed_kernel1 = create_test_kernel("11c52d250b34a0862edc29db03fbec23b30db6da");
        let fixed_kernel2 = create_test_kernel("22c52d250b34a0862edc29db03fbec23b30db6db");
        let vuln_kernel = create_test_kernel("33c52d250b34a0862edc29db03fbec23b30db6dc");

        let entries = vec![
            DyadEntry {
                vulnerable: vuln_kernel.clone(),
                fixed: fixed_kernel1,
            },
            DyadEntry {
                vulnerable: vuln_kernel,
                fixed: fixed_kernel2,
            },
        ];

        let original_additional_refs = vec![
            "https://example.com/ref1".to_string(),
            "https://example.com/ref2".to_string(),
        ];

        let git_fix_commit = "abcdef1234567890";

        // Test reference generation
        let references_from_osv =
            generate_osv_references(&entries, &original_additional_refs, git_fix_commit);

        assert_eq!(references_from_osv.len(), 3);
        assert!(
            references_from_osv
                .iter()
                .any(|r| r.url == "https://example.com/ref1")
        );
        assert!(
            references_from_osv
                .iter()
                .any(|r| r.url == "https://example.com/ref2")
        );
        assert_eq!(references_from_osv[0].r#type, ReferenceType::Fix);
    }

    #[test]
    fn test_timestamp_format_is_utc_z() {
        let affected_files = vec![];
        let additional_references = vec![];
        let params = OsvRecordParams {
            id_number: "CVE-2023-12345",
            git_fix_commit: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            commit_subject: "test: fix a bug",
            dyad_entries: Vec::new(),
            script_name: "test_script",
            script_version: "1.0",
            additional_references: &additional_references,
            commit_text: "This is the commit text.",
            affected_files: &affected_files,
        };
        let result = generate_json(&params).unwrap();
        let osv: OsvRecord = serde_json::from_str(&result).unwrap();

        // Check that modified and published timestamps end with 'Z'
        assert!(osv.modified.ends_with('Z'), "Modified timestamp should end with Z, got: {}", osv.modified);
        if let Some(published) = osv.published {
            assert!(published.ends_with('Z'), "Published timestamp should end with Z, got: {}", published);
        }
    }
}
