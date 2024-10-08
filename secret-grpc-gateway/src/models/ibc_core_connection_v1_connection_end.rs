/*
 * Secret Network
 *
 * A REST interface for queries and transactions
 *
 * The version of the OpenAPI document: v1.12
 *
 * Generated by: https://openapi-generator.tech
 */

/// IbcCoreConnectionV1ConnectionEnd : ConnectionEnd defines a stateful object on a chain connected to another separate one. NOTE: there must only be 2 defined ConnectionEnds to establish a connection between two chains.

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct IbcCoreConnectionV1ConnectionEnd {
    /// client associated with this connection.
    #[serde(rename = "client_id", skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    /// IBC version which can be utilised to determine encodings or protocols for channels or packets utilising this connection.
    #[serde(rename = "versions", skip_serializing_if = "Option::is_none")]
    pub versions: Option<Vec<crate::models::IbcVersionWhichCanBeUtilisedToDetermineEncodingsOrProtocolsForChannelsOrPacketsUtilisingThisConnectionInner>>,
    /// current state of the connection end.
    #[serde(rename = "state", skip_serializing_if = "Option::is_none")]
    pub state: Option<State>,
    #[serde(rename = "counterparty", skip_serializing_if = "Option::is_none")]
    pub counterparty: Option<Box<crate::models::ConnectionsResponseConnectionsInnerCounterparty>>,
    /// delay period that must pass before a consensus state can be used for packet-verification NOTE: delay period logic is only implemented by some clients.
    #[serde(rename = "delay_period", skip_serializing_if = "Option::is_none")]
    pub delay_period: Option<String>,
}

impl IbcCoreConnectionV1ConnectionEnd {
    /// ConnectionEnd defines a stateful object on a chain connected to another separate one. NOTE: there must only be 2 defined ConnectionEnds to establish a connection between two chains.
    pub fn new() -> IbcCoreConnectionV1ConnectionEnd {
        IbcCoreConnectionV1ConnectionEnd {
            client_id: None,
            versions: None,
            state: None,
            counterparty: None,
            delay_period: None,
        }
    }
}

/// current state of the connection end.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
pub enum State {
    #[serde(rename = "STATE_UNINITIALIZED_UNSPECIFIED")]
    UninitializedUnspecified,
    #[serde(rename = "STATE_INIT")]
    Init,
    #[serde(rename = "STATE_TRYOPEN")]
    Tryopen,
    #[serde(rename = "STATE_OPEN")]
    Open,
}

impl Default for State {
    fn default() -> State {
        Self::UninitializedUnspecified
    }
}
