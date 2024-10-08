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
pub struct DelegatorTotalRewards {
    #[serde(rename = "rewards", skip_serializing_if = "Option::is_none")]
    pub rewards: Option<
        Vec<crate::models::DistributionDelegatorsDelegatorAddrRewardsGetResponseRewardsInner>,
    >,
    #[serde(rename = "total", skip_serializing_if = "Option::is_none")]
    pub total: Option<Vec<crate::models::TxsHashGetResponseTxFeeAmountInner>>,
}

impl DelegatorTotalRewards {
    pub fn new() -> DelegatorTotalRewards {
        DelegatorTotalRewards {
            rewards: None,
            total: None,
        }
    }
}
