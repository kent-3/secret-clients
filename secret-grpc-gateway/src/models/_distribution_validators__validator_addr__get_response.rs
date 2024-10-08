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
pub struct DistributionValidatorsValidatorAddrGetResponse {
    /// bech32 encoded address
    #[serde(rename = "operator_address", skip_serializing_if = "Option::is_none")]
    pub operator_address: Option<String>,
    #[serde(rename = "self_bond_rewards", skip_serializing_if = "Option::is_none")]
    pub self_bond_rewards: Option<Vec<crate::models::TxsHashGetResponseTxFeeAmountInner>>,
    #[serde(rename = "val_commission", skip_serializing_if = "Option::is_none")]
    pub val_commission: Option<Vec<crate::models::TxsHashGetResponseTxFeeAmountInner>>,
}

impl DistributionValidatorsValidatorAddrGetResponse {
    pub fn new() -> DistributionValidatorsValidatorAddrGetResponse {
        DistributionValidatorsValidatorAddrGetResponse {
            operator_address: None,
            self_bond_rewards: None,
            val_commission: None,
        }
    }
}
