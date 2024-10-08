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
pub struct TxsHashGetResponseTxFeeAmountInner {
    #[serde(rename = "denom", skip_serializing_if = "Option::is_none")]
    pub denom: Option<String>,
    #[serde(rename = "amount", skip_serializing_if = "Option::is_none")]
    pub amount: Option<String>,
}

impl TxsHashGetResponseTxFeeAmountInner {
    pub fn new() -> TxsHashGetResponseTxFeeAmountInner {
        TxsHashGetResponseTxFeeAmountInner {
            denom: None,
            amount: None,
        }
    }
}
