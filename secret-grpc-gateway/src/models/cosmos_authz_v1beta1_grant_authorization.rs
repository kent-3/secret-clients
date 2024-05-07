/*
 * Secret Network
 *
 * A REST interface for queries and transactions
 *
 * The version of the OpenAPI document: v1.12
 *
 * Generated by: https://openapi-generator.tech
 */

/// CosmosAuthzV1beta1GrantAuthorization : Since: cosmos-sdk 0.45.2

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CosmosAuthzV1beta1GrantAuthorization {
    #[serde(rename = "granter", skip_serializing_if = "Option::is_none")]
    pub granter: Option<String>,
    #[serde(rename = "grantee", skip_serializing_if = "Option::is_none")]
    pub grantee: Option<String>,
    #[serde(rename = "authorization", skip_serializing_if = "Option::is_none")]
    pub authorization: Option<Box<crate::models::AccountsAreTheExistingAccountsInner>>,
    #[serde(rename = "expiration", skip_serializing_if = "Option::is_none")]
    pub expiration: Option<String>,
}

impl CosmosAuthzV1beta1GrantAuthorization {
    /// Since: cosmos-sdk 0.45.2
    pub fn new() -> CosmosAuthzV1beta1GrantAuthorization {
        CosmosAuthzV1beta1GrantAuthorization {
            granter: None,
            grantee: None,
            authorization: None,
            expiration: None,
        }
    }
}
