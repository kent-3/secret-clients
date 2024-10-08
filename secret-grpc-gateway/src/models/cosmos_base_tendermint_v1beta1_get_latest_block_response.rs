/*
 * Secret Network
 *
 * A REST interface for queries and transactions
 *
 * The version of the OpenAPI document: v1.12
 *
 * Generated by: https://openapi-generator.tech
 */

/// CosmosBaseTendermintV1beta1GetLatestBlockResponse : GetLatestBlockResponse is the response type for the Query/GetLatestBlock RPC method.

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CosmosBaseTendermintV1beta1GetLatestBlockResponse {
    #[serde(rename = "block_id", skip_serializing_if = "Option::is_none")]
    pub block_id: Option<Box<crate::models::BlockId1>>,
    #[serde(rename = "block", skip_serializing_if = "Option::is_none")]
    pub block: Option<Box<crate::models::GetLatestBlockResponseBlock>>,
}

impl CosmosBaseTendermintV1beta1GetLatestBlockResponse {
    /// GetLatestBlockResponse is the response type for the Query/GetLatestBlock RPC method.
    pub fn new() -> CosmosBaseTendermintV1beta1GetLatestBlockResponse {
        CosmosBaseTendermintV1beta1GetLatestBlockResponse {
            block_id: None,
            block: None,
        }
    }
}
