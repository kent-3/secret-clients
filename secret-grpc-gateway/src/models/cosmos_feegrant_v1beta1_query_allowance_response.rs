/*
 * Secret Network
 *
 * A REST interface for queries and transactions
 *
 * The version of the OpenAPI document: v1.12
 *
 * Generated by: https://openapi-generator.tech
 */

/// CosmosFeegrantV1beta1QueryAllowanceResponse : QueryAllowanceResponse is the response type for the Query/Allowance RPC method.

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CosmosFeegrantV1beta1QueryAllowanceResponse {
    #[serde(rename = "allowance", skip_serializing_if = "Option::is_none")]
    pub allowance:
        Option<Box<crate::models::GrantIsStoredInTheKvStoreToRecordAGrantWithFullContext>>,
}

impl CosmosFeegrantV1beta1QueryAllowanceResponse {
    /// QueryAllowanceResponse is the response type for the Query/Allowance RPC method.
    pub fn new() -> CosmosFeegrantV1beta1QueryAllowanceResponse {
        CosmosFeegrantV1beta1QueryAllowanceResponse { allowance: None }
    }
}
