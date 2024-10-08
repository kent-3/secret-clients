/*
 * Secret Network
 *
 * A REST interface for queries and transactions
 *
 * The version of the OpenAPI document: v1.12
 *
 * Generated by: https://openapi-generator.tech
 */

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct QueryTotalSupplyResponseIsTheResponseTypeForTheQueryTotalSupplyRpcMethod {
    #[serde(rename = "supply", skip_serializing_if = "Option::is_none")]
    pub supply: Option<Vec<crate::models::AllBalancesResponseBalancesInner>>,
    #[serde(rename = "pagination", skip_serializing_if = "Option::is_none")]
    pub pagination: Option<Box<crate::models::QueryTotalSupplyResponseIsTheResponseTypeForTheQueryTotalSupplyRpcMethodPagination>>,
}

impl QueryTotalSupplyResponseIsTheResponseTypeForTheQueryTotalSupplyRpcMethod {
    pub fn new() -> QueryTotalSupplyResponseIsTheResponseTypeForTheQueryTotalSupplyRpcMethod {
        QueryTotalSupplyResponseIsTheResponseTypeForTheQueryTotalSupplyRpcMethod {
            supply: None,
            pagination: None,
        }
    }
}
