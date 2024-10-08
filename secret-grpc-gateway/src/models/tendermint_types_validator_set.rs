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
pub struct TendermintTypesValidatorSet {
    #[serde(rename = "validators", skip_serializing_if = "Option::is_none")]
    pub validators: Option<Vec<crate::models::GetLatestBlockResponseBlockEvidenceEvidenceInnerLightClientAttackEvidenceConflictingBlockValidatorSetValidatorsInner>>,
    #[serde(rename = "proposer", skip_serializing_if = "Option::is_none")]
    pub proposer: Option<Box<crate::models::GetLatestBlockResponseBlockEvidenceEvidenceInnerLightClientAttackEvidenceConflictingBlockValidatorSetValidatorsInner>>,
    #[serde(rename = "total_voting_power", skip_serializing_if = "Option::is_none")]
    pub total_voting_power: Option<String>,
}

impl TendermintTypesValidatorSet {
    pub fn new() -> TendermintTypesValidatorSet {
        TendermintTypesValidatorSet {
            validators: None,
            proposer: None,
            total_voting_power: None,
        }
    }
}
