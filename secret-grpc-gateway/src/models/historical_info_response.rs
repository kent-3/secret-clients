/*
 * Secret Network
 *
 * A REST interface for queries and transactions
 *
 * The version of the OpenAPI document: v1.12
 *
 * Generated by: https://openapi-generator.tech
 */

/// HistoricalInfoResponse : QueryHistoricalInfoResponse is response type for the Query/HistoricalInfo RPC method.

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct HistoricalInfoResponse {
    #[serde(rename = "hist", skip_serializing_if = "Option::is_none")]
    pub hist: Option<Box<crate::models::HistoricalInfoResponseHist>>,
}

impl HistoricalInfoResponse {
    /// QueryHistoricalInfoResponse is response type for the Query/HistoricalInfo RPC method.
    pub fn new() -> HistoricalInfoResponse {
        HistoricalInfoResponse { hist: None }
    }
}
