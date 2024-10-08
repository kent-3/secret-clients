/*
 * Secret Network
 *
 * A REST interface for queries and transactions
 *
 * The version of the OpenAPI document: v1.12
 *
 * Generated by: https://openapi-generator.tech
 */

/// AnnualProvisionsResponse : QueryAnnualProvisionsResponse is the response type for the Query/AnnualProvisions RPC method.

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AnnualProvisionsResponse {
    /// annual_provisions is the current minting annual provisions value.
    #[serde(rename = "annual_provisions", skip_serializing_if = "Option::is_none")]
    pub annual_provisions: Option<String>,
}

impl AnnualProvisionsResponse {
    /// QueryAnnualProvisionsResponse is the response type for the Query/AnnualProvisions RPC method.
    pub fn new() -> AnnualProvisionsResponse {
        AnnualProvisionsResponse {
            annual_provisions: None,
        }
    }
}
