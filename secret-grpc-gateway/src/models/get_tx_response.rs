/*
 * Secret Network
 *
 * A REST interface for queries and transactions
 *
 * The version of the OpenAPI document: v1.12
 *
 * Generated by: https://openapi-generator.tech
 */

/// GetTxResponse : GetTxResponse is the response type for the Service.GetTx method.

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct GetTxResponse {
    #[serde(rename = "tx", skip_serializing_if = "Option::is_none")]
    pub tx: Option<Box<crate::models::GetTxsEventResponseTxsInner>>,
    #[serde(rename = "tx_response", skip_serializing_if = "Option::is_none")]
    pub tx_response: Option<Box<crate::models::GetTxsEventResponseTxResponsesInner>>,
}

impl GetTxResponse {
    /// GetTxResponse is the response type for the Service.GetTx method.
    pub fn new() -> GetTxResponse {
        GetTxResponse {
            tx: None,
            tx_response: None,
        }
    }
}
