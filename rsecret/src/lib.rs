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

#[cfg(target_arch = "wasm32")]
#[cfg(test)]
mod test {
    use crate::{CreateClientOptions, SecretNetworkClient};
    use wasm_bindgen_test::*;
    use web_sys::console;

    wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

    #[wasm_bindgen_test]
    async fn client_works_in_browser() {
        const GRPC_WEB_URL: &str = "http://localhost:9091";
        const CHAIN_ID: &str = "secretdev-1";

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

        let auth_params = secretrs.query.auth.params().await.unwrap();
        console::log_1(&format!("{auth_params:?}").into());

        let validators = secretrs.all_validators().await.unwrap();
        let validator_monikers: Vec<String> = validators
            .into_iter()
            .map(|v| v.description.unwrap_or_default().moniker)
            .collect();
        console::log_1(&format!("{validator_monikers:?}").into());

        // let mut secret_auth = AuthQueryClient::new(Client::new(GRPC_WEB_URL.to_string()));
        // let request = QueryParamsRequest {};
        // let response = secret_auth.params(request).await.unwrap();

        // let (metadata, response, _extensions) = response.into_parts();
        // println!("Response => {:?}", response);
    }
}
