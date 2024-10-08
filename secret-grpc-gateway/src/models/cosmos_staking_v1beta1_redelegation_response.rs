/*
 * Secret Network
 *
 * A REST interface for queries and transactions
 *
 * The version of the OpenAPI document: v1.12
 *
 * Generated by: https://openapi-generator.tech
 */

/// CosmosStakingV1beta1RedelegationResponse : RedelegationResponse is equivalent to a Redelegation except that its entries contain a balance in addition to shares which is more suitable for client responses.

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CosmosStakingV1beta1RedelegationResponse {
    #[serde(rename = "redelegation", skip_serializing_if = "Option::is_none")]
    pub redelegation:
        Option<Box<crate::models::RedelegationsResponseRedelegationResponsesInnerRedelegation>>,
    #[serde(rename = "entries", skip_serializing_if = "Option::is_none")]
    pub entries:
        Option<Vec<crate::models::RedelegationsResponseRedelegationResponsesInnerEntriesInner>>,
}

impl CosmosStakingV1beta1RedelegationResponse {
    /// RedelegationResponse is equivalent to a Redelegation except that its entries contain a balance in addition to shares which is more suitable for client responses.
    pub fn new() -> CosmosStakingV1beta1RedelegationResponse {
        CosmosStakingV1beta1RedelegationResponse {
            redelegation: None,
            entries: None,
        }
    }
}
