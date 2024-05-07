/*
 * Secret Network
 *
 * A REST interface for queries and transactions
 *
 * The version of the OpenAPI document: v1.12
 *
 * Generated by: https://openapi-generator.tech
 */

/// TransferParamsResponseParams : params defines the parameters of the module.

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct TransferParamsResponseParams {
    /// send_enabled enables or disables all cross-chain token transfers from this chain.
    #[serde(rename = "send_enabled", skip_serializing_if = "Option::is_none")]
    pub send_enabled: Option<bool>,
    /// receive_enabled enables or disables all cross-chain token transfers to this chain.
    #[serde(rename = "receive_enabled", skip_serializing_if = "Option::is_none")]
    pub receive_enabled: Option<bool>,
}

impl TransferParamsResponseParams {
    /// params defines the parameters of the module.
    pub fn new() -> TransferParamsResponseParams {
        TransferParamsResponseParams {
            send_enabled: None,
            receive_enabled: None,
        }
    }
}
