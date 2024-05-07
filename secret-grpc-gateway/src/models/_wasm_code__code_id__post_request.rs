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
pub struct WasmCodeCodeIdPostRequest {
    #[serde(rename = "base_req", skip_serializing_if = "Option::is_none")]
    pub base_req: Option<Box<crate::models::BankAccountsAddressTransfersPostRequestBaseReq>>,
    #[serde(rename = "init_coins", skip_serializing_if = "Option::is_none")]
    pub init_coins: Option<Vec<crate::models::TxsHashGetResponseTxFeeAmountInner>>,
    /// json formatted string
    #[serde(rename = "init_msg", skip_serializing_if = "Option::is_none")]
    pub init_msg: Option<String>,
}

impl WasmCodeCodeIdPostRequest {
    pub fn new() -> WasmCodeCodeIdPostRequest {
        WasmCodeCodeIdPostRequest {
            base_req: None,
            init_coins: None,
            init_msg: None,
        }
    }
}
