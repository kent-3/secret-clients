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
pub struct PrevBlockInfo {
    #[serde(rename = "hash", skip_serializing_if = "Option::is_none")]
    pub hash: Option<String>,
    #[serde(rename = "part_set_header", skip_serializing_if = "Option::is_none")]
    pub part_set_header: Option<Box<crate::models::PartsetHeader>>,
}

impl PrevBlockInfo {
    pub fn new() -> PrevBlockInfo {
        PrevBlockInfo {
            hash: None,
            part_set_header: None,
        }
    }
}
