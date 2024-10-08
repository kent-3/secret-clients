/*
 * Secret Network
 *
 * A REST interface for queries and transactions
 *
 * The version of the OpenAPI document: v1.12
 *
 * Generated by: https://openapi-generator.tech
 */

/// IbcCoreChannelV1State : State defines if a channel is in one of the following states: CLOSED, INIT, TRYOPEN, OPEN or UNINITIALIZED.   - STATE_UNINITIALIZED_UNSPECIFIED: Default State  - STATE_INIT: A channel has just started the opening handshake.  - STATE_TRYOPEN: A channel has acknowledged the handshake step on the counterparty chain.  - STATE_OPEN: A channel has completed the handshake. Open channels are ready to send and receive packets.  - STATE_CLOSED: A channel has been closed and can no longer be used to send or receive packets.

/// State defines if a channel is in one of the following states: CLOSED, INIT, TRYOPEN, OPEN or UNINITIALIZED.   - STATE_UNINITIALIZED_UNSPECIFIED: Default State  - STATE_INIT: A channel has just started the opening handshake.  - STATE_TRYOPEN: A channel has acknowledged the handshake step on the counterparty chain.  - STATE_OPEN: A channel has completed the handshake. Open channels are ready to send and receive packets.  - STATE_CLOSED: A channel has been closed and can no longer be used to send or receive packets.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
pub enum IbcCoreChannelV1State {
    #[serde(rename = "STATE_UNINITIALIZED_UNSPECIFIED")]
    UninitializedUnspecified,
    #[serde(rename = "STATE_INIT")]
    Init,
    #[serde(rename = "STATE_TRYOPEN")]
    Tryopen,
    #[serde(rename = "STATE_OPEN")]
    Open,
    #[serde(rename = "STATE_CLOSED")]
    Closed,
}

impl ToString for IbcCoreChannelV1State {
    fn to_string(&self) -> String {
        match self {
            Self::UninitializedUnspecified => String::from("STATE_UNINITIALIZED_UNSPECIFIED"),
            Self::Init => String::from("STATE_INIT"),
            Self::Tryopen => String::from("STATE_TRYOPEN"),
            Self::Open => String::from("STATE_OPEN"),
            Self::Closed => String::from("STATE_CLOSED"),
        }
    }
}

impl Default for IbcCoreChannelV1State {
    fn default() -> IbcCoreChannelV1State {
        Self::UninitializedUnspecified
    }
}
