/*
 * Secret Network
 *
 * A REST interface for queries and transactions
 *
 * The version of the OpenAPI document: v1.12
 *
 * Generated by: https://openapi-generator.tech
 */

/// RedelegationsResponse : QueryRedelegationsResponse is response type for the Query/Redelegations RPC method.

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RedelegationsResponse {
    #[serde(
        rename = "redelegation_responses",
        skip_serializing_if = "Option::is_none"
    )]
    pub redelegation_responses:
        Option<Vec<crate::models::RedelegationsResponseRedelegationResponsesInner>>,
    #[serde(rename = "pagination", skip_serializing_if = "Option::is_none")]
    pub pagination: Option<Box<crate::models::AccountsResponsePagination>>,
}

impl RedelegationsResponse {
    /// QueryRedelegationsResponse is response type for the Query/Redelegations RPC method.
    pub fn new() -> RedelegationsResponse {
        RedelegationsResponse {
            redelegation_responses: None,
            pagination: None,
        }
    }
}
