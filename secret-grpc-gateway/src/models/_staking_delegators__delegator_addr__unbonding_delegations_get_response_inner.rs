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
pub struct StakingDelegatorsDelegatorAddrUnbondingDelegationsGetResponseInner {
    #[serde(rename = "delegator_address", skip_serializing_if = "Option::is_none")]
    pub delegator_address: Option<String>,
    #[serde(rename = "validator_address", skip_serializing_if = "Option::is_none")]
    pub validator_address: Option<String>,
    #[serde(rename = "initial_balance", skip_serializing_if = "Option::is_none")]
    pub initial_balance: Option<String>,
    #[serde(rename = "balance", skip_serializing_if = "Option::is_none")]
    pub balance: Option<String>,
    #[serde(rename = "creation_height", skip_serializing_if = "Option::is_none")]
    pub creation_height: Option<i32>,
    #[serde(rename = "min_time", skip_serializing_if = "Option::is_none")]
    pub min_time: Option<i32>,
}

impl StakingDelegatorsDelegatorAddrUnbondingDelegationsGetResponseInner {
    pub fn new() -> StakingDelegatorsDelegatorAddrUnbondingDelegationsGetResponseInner {
        StakingDelegatorsDelegatorAddrUnbondingDelegationsGetResponseInner {
            delegator_address: None,
            validator_address: None,
            initial_balance: None,
            balance: None,
            creation_height: None,
            min_time: None,
        }
    }
}
