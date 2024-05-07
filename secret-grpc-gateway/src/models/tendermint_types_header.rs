/*
 * Secret Network
 *
 * A REST interface for queries and transactions
 *
 * The version of the OpenAPI document: v1.12
 *
 * Generated by: https://openapi-generator.tech
 */

/// TendermintTypesHeader : Header defines the structure of a Tendermint block header.

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct TendermintTypesHeader {
    #[serde(rename = "version", skip_serializing_if = "Option::is_none")]
    pub version: Option<Box<crate::models::BasicBlockInfo>>,
    #[serde(rename = "chain_id", skip_serializing_if = "Option::is_none")]
    pub chain_id: Option<String>,
    #[serde(rename = "height", skip_serializing_if = "Option::is_none")]
    pub height: Option<String>,
    #[serde(rename = "time", skip_serializing_if = "Option::is_none")]
    pub time: Option<String>,
    #[serde(rename = "last_block_id", skip_serializing_if = "Option::is_none")]
    pub last_block_id: Option<Box<crate::models::BlockId1>>,
    #[serde(rename = "last_commit_hash", skip_serializing_if = "Option::is_none")]
    pub last_commit_hash: Option<String>,
    #[serde(rename = "data_hash", skip_serializing_if = "Option::is_none")]
    pub data_hash: Option<String>,
    #[serde(rename = "validators_hash", skip_serializing_if = "Option::is_none")]
    pub validators_hash: Option<String>,
    #[serde(
        rename = "next_validators_hash",
        skip_serializing_if = "Option::is_none"
    )]
    pub next_validators_hash: Option<String>,
    #[serde(rename = "consensus_hash", skip_serializing_if = "Option::is_none")]
    pub consensus_hash: Option<String>,
    #[serde(rename = "app_hash", skip_serializing_if = "Option::is_none")]
    pub app_hash: Option<String>,
    #[serde(rename = "last_results_hash", skip_serializing_if = "Option::is_none")]
    pub last_results_hash: Option<String>,
    #[serde(rename = "evidence_hash", skip_serializing_if = "Option::is_none")]
    pub evidence_hash: Option<String>,
    #[serde(rename = "proposer_address", skip_serializing_if = "Option::is_none")]
    pub proposer_address: Option<String>,
    #[serde(rename = "encrypted_random", skip_serializing_if = "Option::is_none")]
    pub encrypted_random: Option<Box<crate::models::EncryptedRandom>>,
}

impl TendermintTypesHeader {
    /// Header defines the structure of a Tendermint block header.
    pub fn new() -> TendermintTypesHeader {
        TendermintTypesHeader {
            version: None,
            chain_id: None,
            height: None,
            time: None,
            last_block_id: None,
            last_commit_hash: None,
            data_hash: None,
            validators_hash: None,
            next_validators_hash: None,
            consensus_hash: None,
            app_hash: None,
            last_results_hash: None,
            evidence_hash: None,
            proposer_address: None,
            encrypted_random: None,
        }
    }
}
