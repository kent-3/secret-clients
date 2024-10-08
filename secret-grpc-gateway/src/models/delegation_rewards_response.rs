/*
 * Secret Network
 *
 * A REST interface for queries and transactions
 *
 * The version of the OpenAPI document: v1.12
 *
 * Generated by: https://openapi-generator.tech
 */

/// DelegationRewardsResponse : QueryDelegationRewardsResponse is the response type for the Query/DelegationRewards RPC method.

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DelegationRewardsResponse {
    /// rewards defines the rewards accrued by a delegation.
    #[serde(rename = "rewards", skip_serializing_if = "Option::is_none")]
    pub rewards: Option<Vec<crate::models::CommunityPoolResponsePoolInner>>,
}

impl DelegationRewardsResponse {
    /// QueryDelegationRewardsResponse is the response type for the Query/DelegationRewards RPC method.
    pub fn new() -> DelegationRewardsResponse {
        DelegationRewardsResponse { rewards: None }
    }
}
