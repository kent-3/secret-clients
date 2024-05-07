/*
 * Secret Network
 *
 * A REST interface for queries and transactions
 *
 * The version of the OpenAPI document: v1.12
 *
 * Generated by: https://openapi-generator.tech
 */

/// ControllerParamsResponseParams : params defines the parameters of the module.

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ControllerParamsResponseParams {
    /// controller_enabled enables or disables the controller submodule.
    #[serde(rename = "controller_enabled", skip_serializing_if = "Option::is_none")]
    pub controller_enabled: Option<bool>,
}

impl ControllerParamsResponseParams {
    /// params defines the parameters of the module.
    pub fn new() -> ControllerParamsResponseParams {
        ControllerParamsResponseParams {
            controller_enabled: None,
        }
    }
}
