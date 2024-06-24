#![allow(unused)]

pub(crate) mod wallet_amino;
pub(crate) mod wallet_proto;

pub use wallet_amino::{AminoSigner, WalletOptions};
pub use wallet_proto::{DirectSigner, Wallet};

pub trait Signer {
    fn sign(&self);
}
