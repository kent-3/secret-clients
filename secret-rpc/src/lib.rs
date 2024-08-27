use crate::consts::{DEFAULT_PORT, TESTNET_CHAIN_ID, TESTNET_ENCLAVE_KEY, TESTNET_HOST};
use crate::error::Result;

pub mod account;
pub mod client;
pub(crate) mod consts;
pub(crate) mod crypto;
pub mod error;
pub mod query;

pub use account::Account;
pub use client::{
    tx::builder::*,
    types::{CodeHash, CodeId, Contract, TxResponse},
    Client,
};
pub use error::Error;

// Re-exports
pub use cosmrs::rpc::Client as TendermintClient;

pub struct SecretRPC {
    /// RPC server URL
    host: String,
    port: u16,
    /// Hex-encoded Enclave Public Key
    enclave_key: String,
    chain_id: String,
}

impl SecretRPC {
    /// Initializes the constructor as a testnet instance
    pub fn new() -> Self {
        Self {
            host: TESTNET_HOST.to_owned(),
            port: DEFAULT_PORT,
            enclave_key: TESTNET_ENCLAVE_KEY.to_owned(),
            chain_id: TESTNET_CHAIN_ID.to_owned(),
        }
    }

    pub fn host(mut self, host: impl Into<String>) -> Self {
        self.host = host.into();
        self
    }

    pub fn port(mut self, port: u16) -> Self {
        self.port = port;
        self
    }

    pub fn enclave_key(mut self, key: impl Into<String>) -> Self {
        self.enclave_key = key.into();
        self
    }

    pub fn chain_id(mut self, id: impl Into<String>) -> Self {
        self.chain_id = id.into();
        self
    }

    pub fn connect(&self) -> Result<Client> {
        let enclave_key = crypto::clone_into_key(&hex::decode(&self.enclave_key)?);

        Client::init(&self.host, self.port, enclave_key, &self.chain_id)
    }
}

impl Default for SecretRPC {
    fn default() -> Self {
        Self::new()
    }
}
