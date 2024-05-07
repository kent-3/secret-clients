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
pub struct UniquePacketIdentifierComprisedOfTheChannelIdPortIdAndSequence {
    #[serde(rename = "port_id", skip_serializing_if = "Option::is_none")]
    pub port_id: Option<String>,
    #[serde(rename = "channel_id", skip_serializing_if = "Option::is_none")]
    pub channel_id: Option<String>,
    #[serde(rename = "sequence", skip_serializing_if = "Option::is_none")]
    pub sequence: Option<String>,
}

impl UniquePacketIdentifierComprisedOfTheChannelIdPortIdAndSequence {
    pub fn new() -> UniquePacketIdentifierComprisedOfTheChannelIdPortIdAndSequence {
        UniquePacketIdentifierComprisedOfTheChannelIdPortIdAndSequence {
            port_id: None,
            channel_id: None,
            sequence: None,
        }
    }
}
