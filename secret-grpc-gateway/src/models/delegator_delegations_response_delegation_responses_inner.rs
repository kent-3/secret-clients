/*
 * Secret Network
 *
 * A REST interface for queries and transactions
 *
 * The version of the OpenAPI document: v1.12
 *
 * Generated by: https://openapi-generator.tech
 */

/// DelegatorDelegationsResponseDelegationResponsesInner : DelegationResponse is equivalent to Delegation except that it contains a balance in addition to shares which is more suitable for client responses.

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DelegatorDelegationsResponseDelegationResponsesInner {
    #[serde(rename = "delegation", skip_serializing_if = "Option::is_none")]
    pub delegation:
        Option<Box<crate::models::DelegatorDelegationsResponseDelegationResponsesInnerDelegation>>,
    #[serde(rename = "balance", skip_serializing_if = "Option::is_none")]
    pub balance: Option<Box<crate::models::AllBalancesResponseBalancesInner>>,
}

impl DelegatorDelegationsResponseDelegationResponsesInner {
    /// DelegationResponse is equivalent to Delegation except that it contains a balance in addition to shares which is more suitable for client responses.
    pub fn new() -> DelegatorDelegationsResponseDelegationResponsesInner {
        DelegatorDelegationsResponseDelegationResponsesInner {
            delegation: None,
            balance: None,
        }
    }
}
