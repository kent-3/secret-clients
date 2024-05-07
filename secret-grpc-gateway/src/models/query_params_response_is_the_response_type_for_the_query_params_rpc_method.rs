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
pub struct QueryParamsResponseIsTheResponseTypeForTheQueryParamsRpcMethod {
    #[serde(rename = "params", skip_serializing_if = "Option::is_none")]
    pub params: Option<
        Box<crate::models::QueryParamsResponseIsTheResponseTypeForTheQueryParamsRpcMethodParams>,
    >,
}

impl QueryParamsResponseIsTheResponseTypeForTheQueryParamsRpcMethod {
    pub fn new() -> QueryParamsResponseIsTheResponseTypeForTheQueryParamsRpcMethod {
        QueryParamsResponseIsTheResponseTypeForTheQueryParamsRpcMethod { params: None }
    }
}
