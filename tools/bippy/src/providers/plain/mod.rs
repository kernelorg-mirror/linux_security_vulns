use anyhow::Result;
use crate::providers::{VulnerabilityProvider, VulnerabilityRecordParams};

/// Plain text provider implementation
/// This provider generates simple plain text output for demonstrations
pub struct PlainProvider;

impl PlainProvider {
    pub fn new() -> Self {
        PlainProvider
    }
}

impl VulnerabilityProvider for PlainProvider {
    fn generate_json(&self, params: &VulnerabilityRecordParams) -> Result<String> {
        // Generate a simple JSON representation
        let json = format!(
            r#"{{
    "id": "{}",
    "type": "plain",
    "fix_commit": "{}",
    "subject": "{}",
    "description": "{}",
    "affected_files": [{}],
    "references": [{}]
}}"#,
            params.vuln_id,
            params.git_sha_full,
            params.commit_subject,
            params.commit_text.lines().take(3).collect::<Vec<_>>().join(" "),
            params.affected_files.iter()
                .map(|f| format!(r#""{}""#, f))
                .collect::<Vec<_>>()
                .join(", "),
            params.additional_references.iter()
                .map(|r| format!(r#""{}""#, r))
                .collect::<Vec<_>>()
                .join(", ")
        );

        Ok(json)
    }

    fn generate_mbox(&self, params: &VulnerabilityRecordParams) -> Result<String> {
        // Generate a simple plain text mbox format
        let mbox = format!(
            r#"From plain-provider Mon Sep 17 00:00:00 2001
From: {} <{}>
To: <security@example.org>
Subject: {}: {}

=== PLAIN TEXT VULNERABILITY ANNOUNCEMENT ===

Vulnerability ID: {}
Fix Commit: {}

Description:
------------
{}

Affected Files:
--------------
{}

Vulnerable/Fixed Versions:
-------------------------
{}

References:
----------
{}

---
This is a plain text vulnerability announcement generated for demonstration purposes.
"#,
            params.user_name,
            params.user_email,
            params.vuln_id,
            params.commit_subject,
            params.vuln_id,
            params.git_sha_full,
            params.commit_text,
            params.affected_files.iter()
                .map(|f| format!("- {}", f))
                .collect::<Vec<_>>()
                .join("\n"),
            self.format_version_info(&params.dyad_entries),
            params.additional_references.iter()
                .map(|r| format!("- {}", r))
                .collect::<Vec<_>>()
                .join("\n")
        );

        Ok(mbox)
    }

    fn name(&self) -> &'static str {
        "Plain"
    }

    fn user_env_var(&self) -> &'static str {
        "PLAIN_USER"
    }

    fn validate_id(&self, id: &str) -> Result<()> {
        // Plain provider accepts any ID format
        if id.is_empty() {
            Err(anyhow::anyhow!("Vulnerability ID cannot be empty"))
        } else {
            Ok(())
        }
    }
}

impl PlainProvider {
    fn format_version_info(&self, dyad_entries: &[crate::models::DyadEntry]) -> String {
        if dyad_entries.is_empty() {
            return "No version information available".to_string();
        }

        dyad_entries.iter()
            .map(|entry| {
                if entry.fixed.is_empty() {
                    format!("- Introduced in {} ({})",
                        entry.vulnerable.version(),
                        entry.vulnerable.git_id())
                } else if entry.vulnerable.is_empty() {
                    format!("- Fixed in {} ({})",
                        entry.fixed.version(),
                        entry.fixed.git_id())
                } else {
                    format!("- Introduced in {} ({}) -> Fixed in {} ({})",
                        entry.vulnerable.version(),
                        entry.vulnerable.git_id(),
                        entry.fixed.version(),
                        entry.fixed.git_id())
                }
            })
            .collect::<Vec<_>>()
            .join("\n")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_plain_provider_validate_id() {
        let provider = PlainProvider::new();

        // Should accept any non-empty ID
        assert!(provider.validate_id("PLAIN-001").is_ok());
        assert!(provider.validate_id("some-id").is_ok());
        assert!(provider.validate_id("123").is_ok());

        // Should reject empty ID
        assert!(provider.validate_id("").is_err());
    }

    #[test]
    fn test_plain_provider_name() {
        let provider = PlainProvider::new();
        assert_eq!(provider.name(), "Plain");
    }

    #[test]
    fn test_plain_provider_env_var() {
        let provider = PlainProvider::new();
        assert_eq!(provider.user_env_var(), "PLAIN_USER");
    }
}
