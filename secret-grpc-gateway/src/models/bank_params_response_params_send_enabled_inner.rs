/*
 * Secret Network
 *
 * A REST interface for queries and transactions
 *
 * The version of the OpenAPI document: v1.12
 *
 * Generated by: https://openapi-generator.tech
 */

/// BankParamsResponseParamsSendEnabledInner : SendEnabled maps coin denom to a send_enabled status (whether a denom is sendable).

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct BankParamsResponseParamsSendEnabledInner {
    #[serde(rename = "denom", skip_serializing_if = "Option::is_none")]
    pub denom: Option<String>,
    #[serde(rename = "enabled", skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
}

impl BankParamsResponseParamsSendEnabledInner {
    /// SendEnabled maps coin denom to a send_enabled status (whether a denom is sendable).
    pub fn new() -> BankParamsResponseParamsSendEnabledInner {
        BankParamsResponseParamsSendEnabledInner {
            denom: None,
            enabled: None,
        }
    }
}
