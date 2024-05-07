/*
 * Secret Network
 *
 * A REST interface for queries and transactions
 *
 * The version of the OpenAPI document: v1.12
 *
 * Generated by: https://openapi-generator.tech
 */

/// SimulateResponseResult : result is the result of the simulation.

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SimulateResponseResult {
    /// Data is any data returned from message or handler execution. It MUST be length prefixed in order to separate data from multiple message executions.
    #[serde(rename = "data", skip_serializing_if = "Option::is_none")]
    pub data: Option<String>,
    /// Log contains the log information from message or handler execution.
    #[serde(rename = "log", skip_serializing_if = "Option::is_none")]
    pub log: Option<String>,
    /// Events contains a slice of Event objects that were emitted during message or handler execution.
    #[serde(rename = "events", skip_serializing_if = "Option::is_none")]
    pub events: Option<Vec<crate::models::SimulateResponseResultEventsInner>>,
}

impl SimulateResponseResult {
    /// result is the result of the simulation.
    pub fn new() -> SimulateResponseResult {
        SimulateResponseResult {
            data: None,
            log: None,
            events: None,
        }
    }
}
