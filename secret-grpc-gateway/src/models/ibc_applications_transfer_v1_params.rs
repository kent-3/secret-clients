/*
 * Secret Network
 *
 * A REST interface for queries and transactions
 *
 * The version of the OpenAPI document: v1.12
 *
 * Generated by: https://openapi-generator.tech
 */

/// IbcApplicationsTransferV1Params : Params defines the set of IBC transfer parameters. NOTE: To prevent a single token from being transferred, set the TransfersEnabled parameter to true and then set the bank module's SendEnabled parameter for the denomination to false.

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct IbcApplicationsTransferV1Params {
    /// send_enabled enables or disables all cross-chain token transfers from this chain.
    #[serde(rename = "send_enabled", skip_serializing_if = "Option::is_none")]
    pub send_enabled: Option<bool>,
    /// receive_enabled enables or disables all cross-chain token transfers to this chain.
    #[serde(rename = "receive_enabled", skip_serializing_if = "Option::is_none")]
    pub receive_enabled: Option<bool>,
}

impl IbcApplicationsTransferV1Params {
    /// Params defines the set of IBC transfer parameters. NOTE: To prevent a single token from being transferred, set the TransfersEnabled parameter to true and then set the bank module's SendEnabled parameter for the denomination to false.
    pub fn new() -> IbcApplicationsTransferV1Params {
        IbcApplicationsTransferV1Params {
            send_enabled: None,
            receive_enabled: None,
        }
    }
}
