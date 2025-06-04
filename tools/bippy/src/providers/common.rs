// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (c) 2025 - Sasha Levin <sashal@kernel.org>

//! Common data structures used across different vulnerability providers

use serde::{Deserialize, Serialize};

/// Version range information used by providers
#[derive(Debug, Serialize, Deserialize, Default)]
pub struct VersionRange {
    /// Version string, in a specific type, see versionType below for the valid types
    /// 0 means "beginning of time"
    pub version: String,

    #[serde(rename = "lessThan", skip_serializing_if = "Option::is_none")]
    pub less_than: Option<String>,

    #[serde(rename = "lessThanOrEqual", skip_serializing_if = "Option::is_none")]
    pub less_than_or_equal: Option<String>,

    /// valid values are "affected", "unaffected", or "unknown"
    pub status: String,

    /// valid values are "custom", "git", "maven", "python", "rpm", or "semver"
    /// We will just stick with "git" or "semver" as that's the most sane for us, even though
    /// "semver" is NOT what Linux kernel release numbers represent at all.
    #[serde(rename = "versionType", skip_serializing_if = "Option::is_none")]
    pub version_type: Option<String>,
}

/// CPE (Common Platform Enumeration) match information
#[derive(Debug, Serialize, Deserialize, Default)]
pub struct CpeMatch {
    /// boolean value, must be "true" or "false"
    pub vulnerable: bool,

    /// critera for us is always going to be: "cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*"
    pub criteria: String,

    #[serde(rename = "versionStartIncluding")]
    #[serde(skip_serializing_if = "String::is_empty")]
    pub version_start_including: String,

    #[serde(rename = "versionEndExcluding")]
    #[serde(skip_serializing_if = "String::is_empty")]
    pub version_end_excluding: String,

    /// Odds are we will not use the following fields, but they are here
    /// just to round out the documentation of the schema
    #[serde(rename = "matchCriteriaId")]
    #[serde(skip_serializing_if = "String::is_empty")]
    pub match_criteria_id: String,

    #[serde(rename = "versionStartExcluding")]
    #[serde(skip_serializing_if = "String::is_empty")]
    pub version_start_excluding: String,

    #[serde(rename = "versionEndIncluding")]
    #[serde(skip_serializing_if = "String::is_empty")]
    pub version_end_including: String,
}

/// CPE nodes for vulnerability applicability
#[derive(Debug, Serialize, Deserialize)]
pub struct CpeNodes {
    /// must be "OR" or "AND"
    pub operator: String,
    /// boolean value, must be "true" or "false"
    pub negate: bool,
    #[serde(rename = "cpeMatch")]
    pub cpe_match: Vec<CpeMatch>,
}
