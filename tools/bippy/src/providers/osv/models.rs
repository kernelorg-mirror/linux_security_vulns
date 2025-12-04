use serde::{Deserialize, Serialize};

// --- Main Struct ---

/// The central Open Source Vulnerability (OSV) record.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct OsvRecord {
    // Required fields
    pub schema_version: String,
    pub id: String,
    pub modified: String, // Should be an RFC3339 timestamp (e.g., chrono::DateTime<Utc>)

    // Recommended fields
    #[serde(skip_serializing_if = "Option::is_none")]
    pub published: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub withdrawn: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,

    // Data structures
    #[serde(skip_serializing_if = "Option::is_none")]
    pub affected: Option<Vec<Affected>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub references: Option<Vec<Reference>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub severities: Option<Vec<Severity>>,

    // Optional fields (omitting many, focusing on core)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aliases: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub database_specific: Option<serde_json::Value>,
}

// --- Affected Package Structs ---

/// Describes a package and the version ranges that are affected.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Affected {
    pub package: Package,

    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub ranges: Vec<Range>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub versions: Option<Vec<String>>,

    // The "ecosystem_specific" field can be any JSON value
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ecosystem_specific: Option<serde_json::Value>,

    // The "database_specific" field can be any JSON value
    #[serde(skip_serializing_if = "Option::is_none")]
    pub database_specific: Option<serde_json::Value>,
}

/// Identifies the affected software package.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Package {
    pub name: String,
    pub ecosystem: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub purl: Option<String>, // Package URL (PURL)
}

/// Defines a range of affected versions.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Range {
    pub r#type: RangeType,
    pub events: Vec<Event>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub repo: Option<String>,
}

/// Defines the type of range used (e.g., SEMVER, GIT, ECOSYSTEM).
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RangeType {
    Semver,
    Git,
    Ecosystem,
}

/// An event marking a point in a version range.
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(untagged)]
pub enum Event {
    Introduced { introduced: String },
    LastAffected { last_affected: String },
    Fixed { fixed: String },
    Limit { limit: String },
}

// --- Supporting Structs ---

/// Describes an external reference to the vulnerability.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Reference {
    pub r#type: ReferenceType,
    pub url: String,
}

/// Defines the type of reference (e.g., ADVISORY, REPORT, WEB).
#[derive(PartialEq, Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReferenceType {
    Advisory,
    Article,
    Report,
    Fix,
    Web,
    Resource,
    Detector,
}

/// Defines a severity score for the vulnerability.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Severity {
    pub r#type: SeverityType,
    pub score: String,
}

/// Defines the type of severity scoring (e.g., CVSS_V3, CVSS_V2).
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SeverityType {
    CvssV2,
    CvssV3,
    CvssV31,
    CvssV4,
    Other,
}
