/*
 * Secret Network
 *
 * A REST interface for queries and transactions
 *
 * The version of the OpenAPI document: v1.12
 *
 * Generated by: https://openapi-generator.tech
 */

/// CosmosStakingV1beta1HistoricalInfo : HistoricalInfo contains header and validator information for a given block. It is stored as part of staking module's state, which persists the `n` most recent HistoricalInfo (`n` is set by the staking module's `historical_entries` parameter).

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CosmosStakingV1beta1HistoricalInfo {
    #[serde(rename = "header", skip_serializing_if = "Option::is_none")]
    pub header: Option<Box<crate::models::HistoricalInfoResponseHistHeader>>,
    #[serde(rename = "valset", skip_serializing_if = "Option::is_none")]
    pub valset: Option<Vec<crate::models::DelegatorValidatorsInfoResponseValidatorsInner>>,
}

impl CosmosStakingV1beta1HistoricalInfo {
    /// HistoricalInfo contains header and validator information for a given block. It is stored as part of staking module's state, which persists the `n` most recent HistoricalInfo (`n` is set by the staking module's `historical_entries` parameter).
    pub fn new() -> CosmosStakingV1beta1HistoricalInfo {
        CosmosStakingV1beta1HistoricalInfo {
            header: None,
            valset: None,
        }
    }
}
