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
pub struct QueryTotalAckFeesResponseDefinesTheResponseTypeForTheTotalAckFeesRpc {
    #[serde(rename = "ack_fees", skip_serializing_if = "Option::is_none")]
    pub ack_fees: Option<Vec<crate::models::AllBalancesResponseBalancesInner>>,
}

impl QueryTotalAckFeesResponseDefinesTheResponseTypeForTheTotalAckFeesRpc {
    pub fn new() -> QueryTotalAckFeesResponseDefinesTheResponseTypeForTheTotalAckFeesRpc {
        QueryTotalAckFeesResponseDefinesTheResponseTypeForTheTotalAckFeesRpc { ack_fees: None }
    }
}
