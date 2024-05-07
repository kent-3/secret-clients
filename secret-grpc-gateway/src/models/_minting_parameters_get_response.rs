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
pub struct MintingParametersGetResponse {
    #[serde(rename = "mint_denom", skip_serializing_if = "Option::is_none")]
    pub mint_denom: Option<String>,
    #[serde(
        rename = "inflation_rate_change",
        skip_serializing_if = "Option::is_none"
    )]
    pub inflation_rate_change: Option<String>,
    #[serde(rename = "inflation_max", skip_serializing_if = "Option::is_none")]
    pub inflation_max: Option<String>,
    #[serde(rename = "inflation_min", skip_serializing_if = "Option::is_none")]
    pub inflation_min: Option<String>,
    #[serde(rename = "goal_bonded", skip_serializing_if = "Option::is_none")]
    pub goal_bonded: Option<String>,
    #[serde(rename = "blocks_per_year", skip_serializing_if = "Option::is_none")]
    pub blocks_per_year: Option<String>,
}

impl MintingParametersGetResponse {
    pub fn new() -> MintingParametersGetResponse {
        MintingParametersGetResponse {
            mint_denom: None,
            inflation_rate_change: None,
            inflation_max: None,
            inflation_min: None,
            goal_bonded: None,
            blocks_per_year: None,
        }
    }
}
