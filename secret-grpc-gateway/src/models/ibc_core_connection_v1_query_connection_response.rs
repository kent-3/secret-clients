/*
 * Secret Network
 *
 * A REST interface for queries and transactions
 *
 * The version of the OpenAPI document: v1.12
 *
 * Generated by: https://openapi-generator.tech
 */

/// IbcCoreConnectionV1QueryConnectionResponse : QueryConnectionResponse is the response type for the Query/Connection RPC method. Besides the connection end, it includes a proof and the height from which the proof was retrieved.

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct IbcCoreConnectionV1QueryConnectionResponse {
    #[serde(rename = "connection", skip_serializing_if = "Option::is_none")]
    pub connection: Option<Box<crate::models::ConnectionAssociatedWithTheRequestIdentifier>>,
    #[serde(rename = "proof", skip_serializing_if = "Option::is_none")]
    pub proof: Option<String>,
    #[serde(rename = "proof_height", skip_serializing_if = "Option::is_none")]
    pub proof_height: Option<Box<crate::models::HeightAtWhichTheProofWasRetrieved>>,
}

impl IbcCoreConnectionV1QueryConnectionResponse {
    /// QueryConnectionResponse is the response type for the Query/Connection RPC method. Besides the connection end, it includes a proof and the height from which the proof was retrieved.
    pub fn new() -> IbcCoreConnectionV1QueryConnectionResponse {
        IbcCoreConnectionV1QueryConnectionResponse {
            connection: None,
            proof: None,
            proof_height: None,
        }
    }
}
