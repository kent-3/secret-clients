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
pub struct QuerySecretContractResponse {
    #[serde(rename = "data", skip_serializing_if = "Option::is_none")]
    pub data: Option<String>,
}

impl QuerySecretContractResponse {
    pub fn new() -> QuerySecretContractResponse {
        QuerySecretContractResponse { data: None }
    }
}
