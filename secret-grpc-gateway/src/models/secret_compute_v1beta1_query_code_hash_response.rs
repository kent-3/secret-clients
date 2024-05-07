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
pub struct SecretComputeV1beta1QueryCodeHashResponse {
    #[serde(rename = "code_hash", skip_serializing_if = "Option::is_none")]
    pub code_hash: Option<String>,
}

impl SecretComputeV1beta1QueryCodeHashResponse {
    pub fn new() -> SecretComputeV1beta1QueryCodeHashResponse {
        SecretComputeV1beta1QueryCodeHashResponse { code_hash: None }
    }
}
