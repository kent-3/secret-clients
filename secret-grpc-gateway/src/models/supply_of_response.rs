/*
 * Secret Network
 *
 * A REST interface for queries and transactions
 *
 * The version of the OpenAPI document: v1.12
 *
 * Generated by: https://openapi-generator.tech
 */

/// SupplyOfResponse : QuerySupplyOfResponse is the response type for the Query/SupplyOf RPC method.

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SupplyOfResponse {
    #[serde(rename = "amount", skip_serializing_if = "Option::is_none")]
    pub amount: Option<Box<crate::models::AllBalancesResponseBalancesInner>>,
}

impl SupplyOfResponse {
    /// QuerySupplyOfResponse is the response type for the Query/SupplyOf RPC method.
    pub fn new() -> SupplyOfResponse {
        SupplyOfResponse { amount: None }
    }
}
