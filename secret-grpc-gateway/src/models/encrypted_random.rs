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
pub struct EncryptedRandom {
    #[serde(rename = "random", skip_serializing_if = "Option::is_none")]
    pub random: Option<String>,
    #[serde(rename = "proof", skip_serializing_if = "Option::is_none")]
    pub proof: Option<String>,
}

impl EncryptedRandom {
    pub fn new() -> EncryptedRandom {
        EncryptedRandom {
            random: None,
            proof: None,
        }
    }
}
