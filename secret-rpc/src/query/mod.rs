pub mod auth;
pub mod bank;
pub mod compute;
pub mod staking;

pub use compute::ComputeQuerier;

use ::cosmrs::rpc::endpoint::abci_query::AbciQuery as QueryResponse;

use prost::Message;

use crate::{Error, Result};

fn try_decode_response<T: Message + Default>(response: QueryResponse) -> Result<T> {
    if response.code.is_err() {
        return Err(Error::AbciQuery(response.log.to_string()));
    }

    try_decode_bytes(&response.value)
}

fn try_decode_any<T: Message + Default>(any: ::cosmrs::Any) -> Result<T> {
    try_decode_bytes(&any.value)
}

fn try_decode_bytes<T: Message + Default>(bytes: &[u8]) -> Result<T> {
    let t = T::decode(bytes)?;
    Ok(t)
}
