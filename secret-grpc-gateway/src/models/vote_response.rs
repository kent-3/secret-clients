/*
 * Secret Network
 *
 * A REST interface for queries and transactions
 *
 * The version of the OpenAPI document: v1.12
 *
 * Generated by: https://openapi-generator.tech
 */

/// VoteResponse : QueryVoteResponse is the response type for the Query/Vote RPC method.

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct VoteResponse {
    #[serde(rename = "vote", skip_serializing_if = "Option::is_none")]
    pub vote: Option<Box<crate::models::VotesResponseVotesInner>>,
}

impl VoteResponse {
    /// QueryVoteResponse is the response type for the Query/Vote RPC method.
    pub fn new() -> VoteResponse {
        VoteResponse { vote: None }
    }
}
