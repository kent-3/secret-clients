/*
 * Secret Network
 *
 * A REST interface for queries and transactions
 *
 * The version of the OpenAPI document: v1.12
 *
 * Generated by: https://openapi-generator.tech
 */

/// CosmosSlashingV1beta1ValidatorSigningInfo : ValidatorSigningInfo defines a validator's signing info for monitoring their liveness activity.

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CosmosSlashingV1beta1ValidatorSigningInfo {
    #[serde(rename = "address", skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    #[serde(rename = "start_height", skip_serializing_if = "Option::is_none")]
    pub start_height: Option<String>,
    /// Index which is incremented each time the validator was a bonded in a block and may have signed a precommit or not. This in conjunction with the `SignedBlocksWindow` param determines the index in the `MissedBlocksBitArray`.
    #[serde(rename = "index_offset", skip_serializing_if = "Option::is_none")]
    pub index_offset: Option<String>,
    /// Timestamp until which the validator is jailed due to liveness downtime.
    #[serde(rename = "jailed_until", skip_serializing_if = "Option::is_none")]
    pub jailed_until: Option<String>,
    /// Whether or not a validator has been tombstoned (killed out of validator set). It is set once the validator commits an equivocation or for any other configured misbehiavor.
    #[serde(rename = "tombstoned", skip_serializing_if = "Option::is_none")]
    pub tombstoned: Option<bool>,
    /// A counter kept to avoid unnecessary array reads. Note that `Sum(MissedBlocksBitArray)` always equals `MissedBlocksCounter`.
    #[serde(
        rename = "missed_blocks_counter",
        skip_serializing_if = "Option::is_none"
    )]
    pub missed_blocks_counter: Option<String>,
}

impl CosmosSlashingV1beta1ValidatorSigningInfo {
    /// ValidatorSigningInfo defines a validator's signing info for monitoring their liveness activity.
    pub fn new() -> CosmosSlashingV1beta1ValidatorSigningInfo {
        CosmosSlashingV1beta1ValidatorSigningInfo {
            address: None,
            start_height: None,
            index_offset: None,
            jailed_until: None,
            tombstoned: None,
            missed_blocks_counter: None,
        }
    }
}
