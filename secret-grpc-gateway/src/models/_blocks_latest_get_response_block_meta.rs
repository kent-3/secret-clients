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
pub struct BlocksLatestGetResponseBlockMeta {
    #[serde(rename = "header", skip_serializing_if = "Option::is_none")]
    pub header: Option<Box<crate::models::BlocksLatestGetResponseBlockMetaHeader>>,
    #[serde(rename = "block_id", skip_serializing_if = "Option::is_none")]
    pub block_id: Option<Box<crate::models::BlocksLatestGetResponseBlockMetaHeaderLastBlockId>>,
}

impl BlocksLatestGetResponseBlockMeta {
    pub fn new() -> BlocksLatestGetResponseBlockMeta {
        BlocksLatestGetResponseBlockMeta {
            header: None,
            block_id: None,
        }
    }
}
