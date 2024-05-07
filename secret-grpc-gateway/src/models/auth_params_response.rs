/*
 * Secret Network
 *
 * A REST interface for queries and transactions
 *
 * The version of the OpenAPI document: v1.12
 *
 * Generated by: https://openapi-generator.tech
 */

/// AuthParamsResponse : QueryParamsResponse is the response type for the Query/Params RPC method.

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AuthParamsResponse {
    #[serde(rename = "params", skip_serializing_if = "Option::is_none")]
    pub params: Option<Box<crate::models::AuthParamsResponseParams>>,
}

impl AuthParamsResponse {
    /// QueryParamsResponse is the response type for the Query/Params RPC method.
    pub fn new() -> AuthParamsResponse {
        AuthParamsResponse { params: None }
    }
}
