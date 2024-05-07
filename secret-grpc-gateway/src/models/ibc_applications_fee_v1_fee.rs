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
pub struct IbcApplicationsFeeV1Fee {
    #[serde(rename = "recv_fee", skip_serializing_if = "Option::is_none")]
    pub recv_fee: Option<Vec<crate::models::AllBalancesResponseBalancesInner>>,
    #[serde(rename = "ack_fee", skip_serializing_if = "Option::is_none")]
    pub ack_fee: Option<Vec<crate::models::AllBalancesResponseBalancesInner>>,
    #[serde(rename = "timeout_fee", skip_serializing_if = "Option::is_none")]
    pub timeout_fee: Option<Vec<crate::models::AllBalancesResponseBalancesInner>>,
}

impl IbcApplicationsFeeV1Fee {
    pub fn new() -> IbcApplicationsFeeV1Fee {
        IbcApplicationsFeeV1Fee {
            recv_fee: None,
            ack_fee: None,
            timeout_fee: None,
        }
    }
}
