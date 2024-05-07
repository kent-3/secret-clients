/*
 * Secret Network
 *
 * A REST interface for queries and transactions
 *
 * The version of the OpenAPI document: v1.12
 *
 * Generated by: https://openapi-generator.tech
 */

/// CosmosUpgradeV1beta1ModuleVersion : ModuleVersion specifies a module and its consensus version.  Since: cosmos-sdk 0.43

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CosmosUpgradeV1beta1ModuleVersion {
    #[serde(rename = "name", skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(rename = "version", skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

impl CosmosUpgradeV1beta1ModuleVersion {
    /// ModuleVersion specifies a module and its consensus version.  Since: cosmos-sdk 0.43
    pub fn new() -> CosmosUpgradeV1beta1ModuleVersion {
        CosmosUpgradeV1beta1ModuleVersion {
            name: None,
            version: None,
        }
    }
}
