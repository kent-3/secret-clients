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
pub struct NodeInfoGetResponseApplicationVersion {
    #[serde(rename = "build_tags", skip_serializing_if = "Option::is_none")]
    pub build_tags: Option<String>,
    #[serde(rename = "client_name", skip_serializing_if = "Option::is_none")]
    pub client_name: Option<String>,
    #[serde(rename = "commit", skip_serializing_if = "Option::is_none")]
    pub commit: Option<String>,
    #[serde(rename = "go", skip_serializing_if = "Option::is_none")]
    pub go: Option<String>,
    #[serde(rename = "name", skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(rename = "server_name", skip_serializing_if = "Option::is_none")]
    pub server_name: Option<String>,
    #[serde(rename = "version", skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

impl NodeInfoGetResponseApplicationVersion {
    pub fn new() -> NodeInfoGetResponseApplicationVersion {
        NodeInfoGetResponseApplicationVersion {
            build_tags: None,
            client_name: None,
            commit: None,
            go: None,
            name: None,
            server_name: None,
            version: None,
        }
    }
}
