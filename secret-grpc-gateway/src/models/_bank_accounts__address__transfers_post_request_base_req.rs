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
pub struct BankAccountsAddressTransfersPostRequestBaseReq {
    /// Sender address or Keybase name to generate a transaction
    #[serde(rename = "from", skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
    #[serde(rename = "memo", skip_serializing_if = "Option::is_none")]
    pub memo: Option<String>,
    #[serde(rename = "chain_id", skip_serializing_if = "Option::is_none")]
    pub chain_id: Option<String>,
    #[serde(rename = "account_number", skip_serializing_if = "Option::is_none")]
    pub account_number: Option<String>,
    #[serde(rename = "sequence", skip_serializing_if = "Option::is_none")]
    pub sequence: Option<String>,
    #[serde(rename = "gas", skip_serializing_if = "Option::is_none")]
    pub gas: Option<String>,
    #[serde(rename = "gas_adjustment", skip_serializing_if = "Option::is_none")]
    pub gas_adjustment: Option<String>,
    #[serde(rename = "fees", skip_serializing_if = "Option::is_none")]
    pub fees: Option<Vec<crate::models::TxsHashGetResponseTxFeeAmountInner>>,
    /// Estimate gas for a transaction (cannot be used in conjunction with generate_only)
    #[serde(rename = "simulate", skip_serializing_if = "Option::is_none")]
    pub simulate: Option<bool>,
}

impl BankAccountsAddressTransfersPostRequestBaseReq {
    pub fn new() -> BankAccountsAddressTransfersPostRequestBaseReq {
        BankAccountsAddressTransfersPostRequestBaseReq {
            from: None,
            memo: None,
            chain_id: None,
            account_number: None,
            sequence: None,
            gas: None,
            gas_adjustment: None,
            fees: None,
            simulate: None,
        }
    }
}
