#![allow(unused)]

use async_trait::async_trait;
use secretrs::tx::SignMode;

pub(crate) mod wallet_amino;
pub(crate) mod wallet_proto;

pub use wallet_amino::{AccountData, AminoSignResponse, AminoSigner, StdSignDoc, WalletOptions};
pub use wallet_proto::{DirectSignResponse, DirectSigner, SignDocVariant, Wallet};

#[async_trait]
pub trait Signer: std::fmt::Debug {
    type Error: std::error::Error + std::fmt::Debug;

    /// Get AccountData array from wallet. Rejects if not enabled.
    async fn get_accounts(&self) -> std::result::Result<Vec<AccountData>, Self::Error>;

    /// Get [SignMode] for signing a tx.
    async fn get_sign_mode(&self) -> std::result::Result<SignMode, Self::Error>;

    /// Request signature from whichever key corresponds to provided bech32-encoded address. Rejects if not enabled.
    ///
    /// The signer implementation may offer the user the ability to override parts of the sign_doc. It must
    /// return the doc that was signed in the response.
    async fn sign_amino(
        &self,
        signer_address: &str,
        sign_doc: StdSignDoc,
    ) -> std::result::Result<AminoSignResponse, Self::Error>;

    async fn sign_permit(
        &self,
        signer_address: &str,
        sign_doc: StdSignDoc,
    ) -> std::result::Result<AminoSignResponse, Self::Error>;

    async fn sign_direct(
        &self,
        signer_address: &str,
        sign_doc: SignDocVariant,
    ) -> std::result::Result<DirectSignResponse, Self::Error>;
}
