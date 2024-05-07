/*
 * Secret Network
 *
 * A REST interface for queries and transactions
 *
 * The version of the OpenAPI document: v1.12
 *
 * Generated by: https://openapi-generator.tech
 */

/// AbsoluteTxPositionCanBeUsedToSortContracts1 : Created Tx position when the contract was instantiated.

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AbsoluteTxPositionCanBeUsedToSortContracts1 {
    #[serde(rename = "block_height", skip_serializing_if = "Option::is_none")]
    pub block_height: Option<String>,
    #[serde(rename = "tx_index", skip_serializing_if = "Option::is_none")]
    pub tx_index: Option<String>,
}

impl AbsoluteTxPositionCanBeUsedToSortContracts1 {
    /// Created Tx position when the contract was instantiated.
    pub fn new() -> AbsoluteTxPositionCanBeUsedToSortContracts1 {
        AbsoluteTxPositionCanBeUsedToSortContracts1 {
            block_height: None,
            tx_index: None,
        }
    }
}
