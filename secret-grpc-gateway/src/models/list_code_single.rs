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
pub struct ListCodeSingle {
    #[serde(rename = "id", skip_serializing_if = "Option::is_none")]
    pub id: Option<f32>,
    #[serde(rename = "creator", skip_serializing_if = "Option::is_none")]
    pub creator: Option<String>,
    #[serde(rename = "data_hash", skip_serializing_if = "Option::is_none")]
    pub data_hash: Option<String>,
    #[serde(rename = "source", skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(rename = "builder", skip_serializing_if = "Option::is_none")]
    pub builder: Option<String>,
}

impl ListCodeSingle {
    pub fn new() -> ListCodeSingle {
        ListCodeSingle {
            id: None,
            creator: None,
            data_hash: None,
            source: None,
            builder: None,
        }
    }
}
