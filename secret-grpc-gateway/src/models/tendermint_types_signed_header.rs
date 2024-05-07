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
pub struct TendermintTypesSignedHeader {
    #[serde(rename = "header", skip_serializing_if = "Option::is_none")]
    pub header: Option<Box<crate::models::GetLatestBlockResponseBlockHeader>>,
    #[serde(rename = "commit", skip_serializing_if = "Option::is_none")]
    pub commit: Option<Box<crate::models::GetLatestBlockResponseBlockEvidenceEvidenceInnerLightClientAttackEvidenceConflictingBlockSignedHeaderCommit>>,
}

impl TendermintTypesSignedHeader {
    pub fn new() -> TendermintTypesSignedHeader {
        TendermintTypesSignedHeader {
            header: None,
            commit: None,
        }
    }
}
