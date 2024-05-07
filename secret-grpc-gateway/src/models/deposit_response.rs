/*
 * Secret Network
 *
 * A REST interface for queries and transactions
 *
 * The version of the OpenAPI document: v1.12
 *
 * Generated by: https://openapi-generator.tech
 */

/// DepositResponse : QueryDepositResponse is the response type for the Query/Deposit RPC method.

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DepositResponse {
    #[serde(rename = "deposit", skip_serializing_if = "Option::is_none")]
    pub deposit: Option<Box<crate::models::DepositsResponseDepositsInner>>,
}

impl DepositResponse {
    /// QueryDepositResponse is the response type for the Query/Deposit RPC method.
    pub fn new() -> DepositResponse {
        DepositResponse { deposit: None }
    }
}
