/*
 * Secret Network
 *
 * A REST interface for queries and transactions
 *
 * The version of the OpenAPI document: v1.12
 *
 * Generated by: https://openapi-generator.tech
 */

/// BroadcastTxResponse : BroadcastTxResponse is the response type for the Service.BroadcastTx method.

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct BroadcastTxResponse {
    #[serde(rename = "tx_response", skip_serializing_if = "Option::is_none")]
    pub tx_response: Option<Box<crate::models::GetTxsEventResponseTxResponsesInner>>,
}

impl BroadcastTxResponse {
    /// BroadcastTxResponse is the response type for the Service.BroadcastTx method.
    pub fn new() -> BroadcastTxResponse {
        BroadcastTxResponse { tx_response: None }
    }
}
