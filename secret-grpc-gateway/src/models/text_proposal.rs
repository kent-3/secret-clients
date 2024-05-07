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
pub struct TextProposal {
    #[serde(rename = "proposal_id", skip_serializing_if = "Option::is_none")]
    pub proposal_id: Option<i32>,
    #[serde(rename = "title", skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(rename = "description", skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(rename = "proposal_type", skip_serializing_if = "Option::is_none")]
    pub proposal_type: Option<String>,
    #[serde(rename = "proposal_status", skip_serializing_if = "Option::is_none")]
    pub proposal_status: Option<String>,
    #[serde(rename = "final_tally_result", skip_serializing_if = "Option::is_none")]
    pub final_tally_result:
        Option<Box<crate::models::GovProposalsGetResponseInnerFinalTallyResult>>,
    #[serde(rename = "submit_time", skip_serializing_if = "Option::is_none")]
    pub submit_time: Option<String>,
    #[serde(rename = "total_deposit", skip_serializing_if = "Option::is_none")]
    pub total_deposit: Option<Vec<crate::models::TxsHashGetResponseTxFeeAmountInner>>,
    #[serde(rename = "voting_start_time", skip_serializing_if = "Option::is_none")]
    pub voting_start_time: Option<String>,
}

impl TextProposal {
    pub fn new() -> TextProposal {
        TextProposal {
            proposal_id: None,
            title: None,
            description: None,
            proposal_type: None,
            proposal_status: None,
            final_tally_result: None,
            submit_time: None,
            total_deposit: None,
            voting_start_time: None,
        }
    }
}
