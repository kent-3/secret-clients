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
pub struct CodeIdContracts {
    #[serde(rename = "height", skip_serializing_if = "Option::is_none")]
    pub height: Option<String>,
    #[serde(rename = "result", skip_serializing_if = "Option::is_none")]
    pub result: Option<Vec<crate::models::WasmCodeCodeIdContractsGetResponseResultResultInner>>,
}

impl CodeIdContracts {
    pub fn new() -> CodeIdContracts {
        CodeIdContracts {
            height: None,
            result: None,
        }
    }
}
