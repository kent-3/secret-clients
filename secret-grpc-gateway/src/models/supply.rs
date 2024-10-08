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
pub struct Supply {
    #[serde(rename = "total", skip_serializing_if = "Option::is_none")]
    pub total: Option<Vec<crate::models::TxsHashGetResponseTxFeeAmountInner>>,
}

impl Supply {
    pub fn new() -> Supply {
        Supply { total: None }
    }
}
