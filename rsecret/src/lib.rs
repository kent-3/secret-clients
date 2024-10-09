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

pub mod account;
mod error;
pub mod query;
pub mod secret_client;
pub mod wallet;

mod bonus;

pub(crate) mod macros;

// TODO:
pub mod tx;

pub use error::{Error, Result};
pub use secret_client::{CreateClientOptions, SecretNetworkClient, TxOptions};

// TODO: create a "mini" SecretNetworkClient for the most common types of queries and txs
// TODO: create a "read-only" SecretNetworkClient for queries

#[cfg(target_arch = "wasm32")]
#[cfg(test)]
mod test {
    use crate::{CreateClientOptions, SecretNetworkClient};
    use color_eyre::Result;
    use wasm_bindgen_test::*;
    use web_sys::console;

    wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

    // const GRPC_WEB_URL: &str = "https://grpc.mainnet.secretsaturn.net";
    // const CHAIN_ID: &str = "secret-4";

    const GRPC_WEB_URL: &str = "http://localhost:9091";
    const CHAIN_ID: &str = "secretdev-1";

    #[wasm_bindgen_test]
    async fn test_latest_block() -> Result<()> {
        let options = CreateClientOptions {
            url: GRPC_WEB_URL,
            chain_id: CHAIN_ID,
            ..Default::default()
        };

        let web_wasm_client = ::tonic_web_wasm_client::Client::new(GRPC_WEB_URL.to_string());
        let secretrs = SecretNetworkClient::new(web_wasm_client, options).unwrap();

        let latest_block = secretrs.query.tendermint.get_latest_block().await.unwrap();
        let latest_block_height = latest_block.header.height;
        console::log_1(&format!("Latest Block Height: {latest_block_height}").into());

        Ok(())
    }

    #[wasm_bindgen_test]
    async fn test_validators() -> Result<()> {
        let options = CreateClientOptions {
            url: GRPC_WEB_URL,
            chain_id: CHAIN_ID,
            ..Default::default()
        };

        let web_wasm_client = ::tonic_web_wasm_client::Client::new(GRPC_WEB_URL.to_string());
        let secretrs = SecretNetworkClient::new(web_wasm_client, options).unwrap();

        let validators = secretrs.all_validators().await.unwrap();
        let validator_monikers: Vec<String> = validators
            .into_iter()
            .map(|v| v.description.unwrap_or_default().moniker)
            .collect();
        console::log_1(&format!("{validator_monikers:?}").into());

        Ok(())
    }

    #[wasm_bindgen_test]
    async fn test_auth_params() -> Result<()> {
        let options = CreateClientOptions {
            url: GRPC_WEB_URL,
            chain_id: CHAIN_ID,
            ..Default::default()
        };

        let web_wasm_client = ::tonic_web_wasm_client::Client::new(GRPC_WEB_URL.to_string());
        let secretrs = SecretNetworkClient::new(web_wasm_client, options).unwrap();

        let auth_params = secretrs.query.auth.params().await.unwrap();
        console::log_1(&format!("{auth_params:?}").into());

        Ok(())
    }

    #[wasm_bindgen_test]
    #[ignore]
    async fn client_works_in_browser() -> Result<()> {
        let options = CreateClientOptions {
            url: GRPC_WEB_URL,
            chain_id: CHAIN_ID,
            ..Default::default()
        };

        let web_wasm_client = ::tonic_web_wasm_client::Client::new(GRPC_WEB_URL.to_string());
        let secretrs = SecretNetworkClient::new(web_wasm_client, options).unwrap();

        let contract_address = "secret1s09x2xvfd2lp2skgzm29w2xtena7s8fq98v852";
        let code_hash = "9a00ca4ad505e9be7e6e6dddf8d939b7ec7e9ac8e109c8681f10db9cacb36d42";
        let query = QueryMsg::TokenInfo {};

        let response = secretrs
            .query
            .compute
            .query_secret_contract(contract_address, code_hash, query)
            .await?;
        console::log_1(&format!("{response}").into());

        Ok(())
    }

    use serde::{Deserialize, Serialize};

    #[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
    #[serde(rename_all = "snake_case")]
    pub enum QueryMsg {
        TokenInfo {},
        MemberCode { address: String, key: String },
        ValidCodes { codes: Vec<String> },
    }

    #[derive(Serialize, Deserialize, Debug)]
    #[serde(rename_all = "snake_case")]
    pub enum QueryAnswer {
        TokenInfo {
            name: String,
            symbol: String,
            decimals: u8,
            total_supply: String,
        },
        MemberCode {
            code: String,
        },
        ValidCodes {
            codes: Vec<String>,
        },
        ViewingKeyError {
            msg: String,
        },
    }
}
