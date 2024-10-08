/*
 * Secret Network
 *
 * A REST interface for queries and transactions
 *
 * The version of the OpenAPI document: v1.12
 *
 * Generated by: https://openapi-generator.tech
 */

/// ProposalsResponseProposalsInnerFinalTallyResult : TallyResult defines a standard tally for a governance proposal.

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ProposalsResponseProposalsInnerFinalTallyResult {
    #[serde(rename = "true", skip_serializing_if = "Option::is_none")]
    pub r#true: Option<String>,
    #[serde(rename = "abstain", skip_serializing_if = "Option::is_none")]
    pub abstain: Option<String>,
    #[serde(rename = "false", skip_serializing_if = "Option::is_none")]
    pub r#false: Option<String>,
    #[serde(rename = "no_with_veto", skip_serializing_if = "Option::is_none")]
    pub no_with_veto: Option<String>,
}

impl ProposalsResponseProposalsInnerFinalTallyResult {
    /// TallyResult defines a standard tally for a governance proposal.
    pub fn new() -> ProposalsResponseProposalsInnerFinalTallyResult {
        ProposalsResponseProposalsInnerFinalTallyResult {
            r#true: None,
            abstain: None,
            r#false: None,
            no_with_veto: None,
        }
    }
}
