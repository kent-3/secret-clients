/*
 * Secret Network
 *
 * A REST interface for queries and transactions
 *
 * The version of the OpenAPI document: v1.12
 *
 * Generated by: https://openapi-generator.tech
 */

/// CommunityPoolResponsePoolInner : DecCoin defines a token with a denomination and a decimal amount.  NOTE: The amount field is an Dec which implements the custom method signatures required by gogoproto.

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CommunityPoolResponsePoolInner {
    #[serde(rename = "denom", skip_serializing_if = "Option::is_none")]
    pub denom: Option<String>,
    #[serde(rename = "amount", skip_serializing_if = "Option::is_none")]
    pub amount: Option<String>,
}

impl CommunityPoolResponsePoolInner {
    /// DecCoin defines a token with a denomination and a decimal amount.  NOTE: The amount field is an Dec which implements the custom method signatures required by gogoproto.
    pub fn new() -> CommunityPoolResponsePoolInner {
        CommunityPoolResponsePoolInner {
            denom: None,
            amount: None,
        }
    }
}
