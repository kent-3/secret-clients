//! A secret.js clone for Rust.

#![warn(
    missing_debug_implementations,
    // missing_docs,
    rust_2018_idioms,
    // unreachable_pub
)]
#![deny(rustdoc::broken_intra_doc_links)]
#![doc(test(no_crate_inject, attr(deny(rust_2018_idioms))))]
#![cfg_attr(docsrs, feature(doc_cfg))]

pub mod bonus;
mod error;
mod query;
mod secret_network_client;
mod tx;
pub mod wallet;

pub use error::{Error, Result};
pub use query::Querier;
pub use secret_network_client::{CreateClientOptions, SecretNetworkClient, TxOptions};
pub use tx::{BankServiceClient, TxSender};
