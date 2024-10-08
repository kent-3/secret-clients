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
pub struct GetLatestBlockResponseBlockEvidenceEvidenceInner {
    #[serde(rename = "duplicate_vote_evidence", skip_serializing_if = "Option::is_none")]
    pub duplicate_vote_evidence: Option<Box<crate::models::GetLatestBlockResponseBlockEvidenceEvidenceInnerDuplicateVoteEvidence>>,
    #[serde(rename = "light_client_attack_evidence", skip_serializing_if = "Option::is_none")]
    pub light_client_attack_evidence: Option<Box<crate::models::GetLatestBlockResponseBlockEvidenceEvidenceInnerLightClientAttackEvidence>>,
}

impl GetLatestBlockResponseBlockEvidenceEvidenceInner {
    pub fn new() -> GetLatestBlockResponseBlockEvidenceEvidenceInner {
        GetLatestBlockResponseBlockEvidenceEvidenceInner {
            duplicate_vote_evidence: None,
            light_client_attack_evidence: None,
        }
    }
}
