/*
 * Secret Network
 *
 * A REST interface for queries and transactions
 *
 * The version of the OpenAPI document: v1.12
 *
 * Generated by: https://openapi-generator.tech
 */

/// DepositsResponseDepositsInner : Deposit defines an amount deposited by an account address to an active proposal.

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DepositsResponseDepositsInner {
    #[serde(rename = "proposal_id", skip_serializing_if = "Option::is_none")]
    pub proposal_id: Option<String>,
    #[serde(rename = "depositor", skip_serializing_if = "Option::is_none")]
    pub depositor: Option<String>,
    #[serde(rename = "amount", skip_serializing_if = "Option::is_none")]
    pub amount: Option<Vec<crate::models::AllBalancesResponseBalancesInner>>,
}

impl DepositsResponseDepositsInner {
    /// Deposit defines an amount deposited by an account address to an active proposal.
    pub fn new() -> DepositsResponseDepositsInner {
        DepositsResponseDepositsInner {
            proposal_id: None,
            depositor: None,
            amount: None,
        }
    }
}
