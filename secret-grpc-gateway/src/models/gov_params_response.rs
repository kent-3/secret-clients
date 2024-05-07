/*
 * Secret Network
 *
 * A REST interface for queries and transactions
 *
 * The version of the OpenAPI document: v1.12
 *
 * Generated by: https://openapi-generator.tech
 */

/// GovParamsResponse : QueryParamsResponse is the response type for the Query/Params RPC method.

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct GovParamsResponse {
    #[serde(rename = "voting_params", skip_serializing_if = "Option::is_none")]
    pub voting_params: Option<Box<crate::models::GovParamsResponseVotingParams>>,
    #[serde(rename = "deposit_params", skip_serializing_if = "Option::is_none")]
    pub deposit_params: Option<Box<crate::models::GovParamsResponseDepositParams>>,
    #[serde(rename = "tally_params", skip_serializing_if = "Option::is_none")]
    pub tally_params: Option<Box<crate::models::GovParamsResponseTallyParams>>,
}

impl GovParamsResponse {
    /// QueryParamsResponse is the response type for the Query/Params RPC method.
    pub fn new() -> GovParamsResponse {
        GovParamsResponse {
            voting_params: None,
            deposit_params: None,
            tally_params: None,
        }
    }
}
