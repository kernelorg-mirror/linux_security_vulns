// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (c) 2025 - Sasha Levin <sashal@kernel.org>

use serde::{Deserialize, Serialize};
use crate::providers::{CpeNodes, VersionRange};

#[derive(Debug, Serialize, Deserialize)]
pub struct CveMetadata {
    #[serde(rename = "assignerOrgId")]
    pub assigner_org_id: String,
    #[serde(rename = "cveID")]
    pub cve_id: String,
    #[serde(rename = "requesterUserId")]
    pub requester_user_id: String,
    pub serial: String,
    pub state: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Description {
    pub lang: String,
    pub value: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ProviderMetadata {
    #[serde(rename = "orgId")]
    pub org_id: String,
}


#[derive(Debug, Serialize, Deserialize)]
pub struct AffectedProduct {
    pub product: String,
    pub vendor: String,
    #[serde(rename = "defaultStatus")]
    pub default_status: String,
    pub repo: String,
    #[serde(rename = "programFiles")]
    pub program_files: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub versions: Vec<VersionRange>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Reference {
    pub url: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Generator {
    pub engine: String,
}


#[derive(Debug, Serialize, Deserialize)]
pub struct CpeApplicability {
    pub nodes: Vec<CpeNodes>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CnaData {
    #[serde(rename = "providerMetadata")]
    pub provider_metadata: ProviderMetadata,
    pub descriptions: Vec<Description>,
    pub affected: Vec<AffectedProduct>,
    #[serde(rename = "cpeApplicability")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub cpe_applicability: Vec<CpeApplicability>,
    pub references: Vec<Reference>,
    pub title: String,
    #[serde(rename = "x_generator")]
    pub x_generator: Generator,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Containers {
    pub cna: CnaData,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CveRecord {
    pub containers: Containers,
    #[serde(rename = "cveMetadata")]
    pub cve_metadata: CveMetadata,
    #[serde(rename = "dataType")]
    pub data_type: String,
    #[serde(rename = "dataVersion")]
    pub data_version: String,
}
