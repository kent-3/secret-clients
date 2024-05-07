/*
 * Secret Network
 *
 * A REST interface for queries and transactions
 *
 * The version of the OpenAPI document: v1.12
 *
 * Generated by: https://openapi-generator.tech
 */

/// CosmosTxV1beta1ModeInfo : ModeInfo describes the signing mode of a single or nested multisig signer.

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CosmosTxV1beta1ModeInfo {
    #[serde(rename = "single", skip_serializing_if = "Option::is_none")]
    pub single: Option<Box<crate::models::SingleRepresentsASingleSigner>>,
    #[serde(rename = "multi", skip_serializing_if = "Option::is_none")]
    pub multi: Option<Box<crate::models::MultiRepresentsANestedMultisigSigner>>,
}

impl CosmosTxV1beta1ModeInfo {
    /// ModeInfo describes the signing mode of a single or nested multisig signer.
    pub fn new() -> CosmosTxV1beta1ModeInfo {
        CosmosTxV1beta1ModeInfo {
            single: None,
            multi: None,
        }
    }
}
