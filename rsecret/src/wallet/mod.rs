#![allow(unused)]

use async_trait::async_trait;
use secretrs::tx::SignMode;
use serde::{de::DeserializeOwned, Serialize};

pub mod error;
pub mod wallet_amino;
pub mod wallet_proto;

pub use error::Error;
pub use wallet_amino::WalletOptions;
pub use wallet_proto::Wallet;

use wallet_amino::{AccountData, AminoSignResponse, StdSignDoc};
use wallet_proto::DirectSignResponse;

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait Signer: std::fmt::Debug {
    /// Get AccountData array from wallet. Rejects if not enabled.
    async fn get_accounts(&self) -> std::result::Result<Vec<AccountData>, Error>;

    /// Get [SignMode] for signing a tx.
    async fn get_sign_mode(&self) -> std::result::Result<SignMode, Error>;

    /// Request signature from whichever key corresponds to provided bech32-encoded address. Rejects if not enabled.
    ///
    /// The signer implementation may offer the user the ability to override parts of the sign_doc. It must
    /// return the doc that was signed in the response.
    async fn sign_amino<T: Serialize + DeserializeOwned + Send + Sync>(
        &self,
        signer_address: &str,
        sign_doc: StdSignDoc<T>,
    ) -> std::result::Result<AminoSignResponse<T>, Error>;

    async fn sign_permit<T: Serialize + DeserializeOwned + Send + Sync>(
        &self,
        signer_address: &str,
        sign_doc: StdSignDoc<T>,
    ) -> std::result::Result<AminoSignResponse<T>, Error>;

    async fn sign_direct(
        &self,
        signer_address: &str,
        sign_doc: secretrs::tx::SignDoc,
    ) -> std::result::Result<DirectSignResponse, Error>;
}
