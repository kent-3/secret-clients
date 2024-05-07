/*
 * Secret Network
 *
 * A REST interface for queries and transactions
 *
 * The version of the OpenAPI document: v1.12
 *
 * Generated by: https://openapi-generator.tech
 */

/// AllowancesResponse : QueryAllowancesResponse is the response type for the Query/Allowances RPC method.

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AllowancesResponse {
    /// allowances are allowance's granted for grantee by granter.
    #[serde(rename = "allowances", skip_serializing_if = "Option::is_none")]
    pub allowances:
        Option<Vec<crate::models::GrantIsStoredInTheKvStoreToRecordAGrantWithFullContext1>>,
    #[serde(rename = "pagination", skip_serializing_if = "Option::is_none")]
    pub pagination: Option<Box<crate::models::GrantsResponsePagination>>,
}

impl AllowancesResponse {
    /// QueryAllowancesResponse is the response type for the Query/Allowances RPC method.
    pub fn new() -> AllowancesResponse {
        AllowancesResponse {
            allowances: None,
            pagination: None,
        }
    }
}
