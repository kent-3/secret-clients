/*
 * Secret Network
 *
 * A REST interface for queries and transactions
 *
 * The version of the OpenAPI document: v1.12
 *
 * Generated by: https://openapi-generator.tech
 */

/// CosmosEvidenceV1beta1QueryEvidenceResponse : QueryEvidenceResponse is the response type for the Query/Evidence RPC method.

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CosmosEvidenceV1beta1QueryEvidenceResponse {
    #[serde(rename = "evidence", skip_serializing_if = "Option::is_none")]
    pub evidence: Option<Box<crate::models::AccountsAreTheExistingAccountsInner>>,
}

impl CosmosEvidenceV1beta1QueryEvidenceResponse {
    /// QueryEvidenceResponse is the response type for the Query/Evidence RPC method.
    pub fn new() -> CosmosEvidenceV1beta1QueryEvidenceResponse {
        CosmosEvidenceV1beta1QueryEvidenceResponse { evidence: None }
    }
}
