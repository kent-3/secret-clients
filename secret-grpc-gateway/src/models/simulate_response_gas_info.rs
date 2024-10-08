/*
 * Secret Network
 *
 * A REST interface for queries and transactions
 *
 * The version of the OpenAPI document: v1.12
 *
 * Generated by: https://openapi-generator.tech
 */

/// SimulateResponseGasInfo : gas_info is the information about gas used in the simulation.

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SimulateResponseGasInfo {
    /// GasWanted is the maximum units of work we allow this tx to perform.
    #[serde(rename = "gas_wanted", skip_serializing_if = "Option::is_none")]
    pub gas_wanted: Option<String>,
    /// GasUsed is the amount of gas actually consumed.
    #[serde(rename = "gas_used", skip_serializing_if = "Option::is_none")]
    pub gas_used: Option<String>,
}

impl SimulateResponseGasInfo {
    /// gas_info is the information about gas used in the simulation.
    pub fn new() -> SimulateResponseGasInfo {
        SimulateResponseGasInfo {
            gas_wanted: None,
            gas_used: None,
        }
    }
}
