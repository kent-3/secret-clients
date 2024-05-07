/*
 * Secret Network
 *
 * A REST interface for queries and transactions
 *
 * The version of the OpenAPI document: v1.12
 *
 * Generated by: https://openapi-generator.tech
 */

/// CosmosAuthV1beta1Params : Params defines the parameters for the auth module.

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CosmosAuthV1beta1Params {
    #[serde(
        rename = "max_memo_characters",
        skip_serializing_if = "Option::is_none"
    )]
    pub max_memo_characters: Option<String>,
    #[serde(rename = "tx_sig_limit", skip_serializing_if = "Option::is_none")]
    pub tx_sig_limit: Option<String>,
    #[serde(
        rename = "tx_size_cost_per_byte",
        skip_serializing_if = "Option::is_none"
    )]
    pub tx_size_cost_per_byte: Option<String>,
    #[serde(
        rename = "sig_verify_cost_ed25519",
        skip_serializing_if = "Option::is_none"
    )]
    pub sig_verify_cost_ed25519: Option<String>,
    #[serde(
        rename = "sig_verify_cost_secp256k1",
        skip_serializing_if = "Option::is_none"
    )]
    pub sig_verify_cost_secp256k1: Option<String>,
}

impl CosmosAuthV1beta1Params {
    /// Params defines the parameters for the auth module.
    pub fn new() -> CosmosAuthV1beta1Params {
        CosmosAuthV1beta1Params {
            max_memo_characters: None,
            tx_sig_limit: None,
            tx_size_cost_per_byte: None,
            sig_verify_cost_ed25519: None,
            sig_verify_cost_secp256k1: None,
        }
    }
}
