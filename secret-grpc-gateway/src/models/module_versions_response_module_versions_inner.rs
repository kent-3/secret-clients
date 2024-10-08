/*
 * Secret Network
 *
 * A REST interface for queries and transactions
 *
 * The version of the OpenAPI document: v1.12
 *
 * Generated by: https://openapi-generator.tech
 */

/// ModuleVersionsResponseModuleVersionsInner : ModuleVersion specifies a module and its consensus version.  Since: cosmos-sdk 0.43

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ModuleVersionsResponseModuleVersionsInner {
    #[serde(rename = "name", skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(rename = "version", skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

impl ModuleVersionsResponseModuleVersionsInner {
    /// ModuleVersion specifies a module and its consensus version.  Since: cosmos-sdk 0.43
    pub fn new() -> ModuleVersionsResponseModuleVersionsInner {
        ModuleVersionsResponseModuleVersionsInner {
            name: None,
            version: None,
        }
    }
}
