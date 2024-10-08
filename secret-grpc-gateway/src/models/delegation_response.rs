/*
 * Secret Network
 *
 * A REST interface for queries and transactions
 *
 * The version of the OpenAPI document: v1.12
 *
 * Generated by: https://openapi-generator.tech
 */

/// DelegationResponse : QueryDelegationResponse is response type for the Query/Delegation RPC method.

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DelegationResponse {
    #[serde(
        rename = "delegation_response",
        skip_serializing_if = "Option::is_none"
    )]
    pub delegation_response:
        Option<Box<crate::models::DelegatorDelegationsResponseDelegationResponsesInner>>,
}

impl DelegationResponse {
    /// QueryDelegationResponse is response type for the Query/Delegation RPC method.
    pub fn new() -> DelegationResponse {
        DelegationResponse {
            delegation_response: None,
        }
    }
}
