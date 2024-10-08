/*
 * Secret Network
 *
 * A REST interface for queries and transactions
 *
 * The version of the OpenAPI document: v1.12
 *
 * Generated by: https://openapi-generator.tech
 */

/// CosmosStakingV1beta1QueryDelegationResponse : QueryDelegationResponse is response type for the Query/Delegation RPC method.

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CosmosStakingV1beta1QueryDelegationResponse {
    #[serde(
        rename = "delegation_response",
        skip_serializing_if = "Option::is_none"
    )]
    pub delegation_response:
        Option<Box<crate::models::DelegatorDelegationsResponseDelegationResponsesInner>>,
}

impl CosmosStakingV1beta1QueryDelegationResponse {
    /// QueryDelegationResponse is response type for the Query/Delegation RPC method.
    pub fn new() -> CosmosStakingV1beta1QueryDelegationResponse {
        CosmosStakingV1beta1QueryDelegationResponse {
            delegation_response: None,
        }
    }
}
