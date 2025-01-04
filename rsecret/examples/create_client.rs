use color_eyre::Result;
use tracing::info;

use rsecret::wallet::{Signer, WalletOptions};
use rsecret::{
    wallet::{wallet_amino::AminoWallet, Wallet},
    CreateClientOptions, SecretNetworkClient,
};
use secretrs::utils::EnigmaUtils;

const GRPC_URL: &str = "http://grpcbin.pulsar.scrttestnet.com:9099";
const CHAIN_ID: &str = "pulsar-3";

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    ::color_eyre::install()?;
    ::tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_line_number(false)
        .with_file(false)
        .without_time()
        .pretty()
        .init();

    let wallet = Wallet::new(AminoWallet::new(None, WalletOptions::default()).unwrap());
    let account_data = wallet.get_accounts().await?;
    let address = account_data[0].address.clone();

    let enigma_utils = EnigmaUtils::new(None, "pulsar-3")?;

    let options = CreateClientOptions::<EnigmaUtils, Wallet> {
        url: GRPC_URL,
        chain_id: CHAIN_ID,
        wallet: Some(wallet),
        wallet_address: Some(address),
        enigma_utils: Some(enigma_utils),
        encryption_seed: None,
    };

    let secretrs = SecretNetworkClient::connect(options).await?;
    info!("SecretNetworkClient created");
    info!("{:#?}", secretrs);

    let latest_block = secretrs.query.tendermint.get_latest_block().await?;
    let latest_block_height = latest_block.header.height;
    info!("{:#?}", latest_block_height);

    Ok(())
}
