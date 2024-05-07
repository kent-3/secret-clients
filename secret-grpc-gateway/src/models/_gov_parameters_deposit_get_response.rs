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
pub struct GovParametersDepositGetResponse {
    #[serde(rename = "min_deposit", skip_serializing_if = "Option::is_none")]
    pub min_deposit: Option<Vec<crate::models::TxsHashGetResponseTxFeeAmountInner>>,
    #[serde(rename = "max_deposit_period", skip_serializing_if = "Option::is_none")]
    pub max_deposit_period: Option<String>,
}

impl GovParametersDepositGetResponse {
    pub fn new() -> GovParametersDepositGetResponse {
        GovParametersDepositGetResponse {
            min_deposit: None,
            max_deposit_period: None,
        }
    }
}
