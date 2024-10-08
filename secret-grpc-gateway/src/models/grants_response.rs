/*
 * Secret Network
 *
 * A REST interface for queries and transactions
 *
 * The version of the OpenAPI document: v1.12
 *
 * Generated by: https://openapi-generator.tech
 */

/// GrantsResponse : QueryGrantsResponse is the response type for the Query/Authorizations RPC method.

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct GrantsResponse {
    /// authorizations is a list of grants granted for grantee by granter.
    #[serde(rename = "grants", skip_serializing_if = "Option::is_none")]
    pub grants: Option<Vec<crate::models::GrantsResponseGrantsInner>>,
    #[serde(rename = "pagination", skip_serializing_if = "Option::is_none")]
    pub pagination: Option<Box<crate::models::GrantsResponsePagination>>,
}

impl GrantsResponse {
    /// QueryGrantsResponse is the response type for the Query/Authorizations RPC method.
    pub fn new() -> GrantsResponse {
        GrantsResponse {
            grants: None,
            pagination: None,
        }
    }
}
