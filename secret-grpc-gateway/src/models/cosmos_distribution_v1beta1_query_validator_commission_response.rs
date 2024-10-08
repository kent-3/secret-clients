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
pub struct CosmosDistributionV1beta1QueryValidatorCommissionResponse {
    #[serde(rename = "commission", skip_serializing_if = "Option::is_none")]
    pub commission: Option<Box<crate::models::QueryValidatorCommissionResponseIsTheResponseTypeForTheQueryValidatorCommissionRpcMethodCommission>>,
}

impl CosmosDistributionV1beta1QueryValidatorCommissionResponse {
    pub fn new() -> CosmosDistributionV1beta1QueryValidatorCommissionResponse {
        CosmosDistributionV1beta1QueryValidatorCommissionResponse { commission: None }
    }
}
