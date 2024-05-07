/*
 * Secret Network
 *
 * A REST interface for queries and transactions
 *
 * The version of the OpenAPI document: v1.12
 *
 * Generated by: https://openapi-generator.tech
 */

/// RouterParamsResponseParams : params defines the parameters of the module.

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RouterParamsResponseParams {
    #[serde(rename = "fee_percentage", skip_serializing_if = "Option::is_none")]
    pub fee_percentage: Option<String>,
}

impl RouterParamsResponseParams {
    /// params defines the parameters of the module.
    pub fn new() -> RouterParamsResponseParams {
        RouterParamsResponseParams {
            fee_percentage: None,
        }
    }
}
