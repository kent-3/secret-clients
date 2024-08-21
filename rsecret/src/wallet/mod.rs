#![allow(unused)]

pub(crate) mod wallet_amino;
pub(crate) mod wallet_proto;

pub use wallet_amino::{AminoSignResponse, AminoSigner, StdSignDoc, WalletOptions};
pub use wallet_proto::{DirectSignResponse, DirectSigner, SignDocVariant, Wallet};

pub trait Signer {
    fn sign(&self);
}
