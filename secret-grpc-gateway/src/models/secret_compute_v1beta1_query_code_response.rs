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
pub struct SecretComputeV1beta1QueryCodeResponse {
    #[serde(rename = "code_info", skip_serializing_if = "Option::is_none")]
    pub code_info: Option<Box<crate::models::CodeResponseCodeInfo>>,
    #[serde(rename = "wasm", skip_serializing_if = "Option::is_none")]
    pub wasm: Option<String>,
}

impl SecretComputeV1beta1QueryCodeResponse {
    pub fn new() -> SecretComputeV1beta1QueryCodeResponse {
        SecretComputeV1beta1QueryCodeResponse {
            code_info: None,
            wasm: None,
        }
    }
}
