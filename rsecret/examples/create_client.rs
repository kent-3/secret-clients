use color_eyre::Result;
use tracing::info;

use rsecret::{wallet::Wallet, CreateClientOptions, SecretNetworkClient};
use secretrs::utils::EnigmaUtils;

const GRPC_URL: &str = "https://secretnetwork-grpc.lavenderfive.com";
const CHAIN_ID: &str = "secret-4";

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

    let options = CreateClientOptions::<EnigmaUtils, Wallet> {
        url: GRPC_URL,
        chain_id: CHAIN_ID,
        ..Default::default()
    };

    let secretrs = SecretNetworkClient::connect(options).await?;
    info!("SecretNetworkClient created");

    let latest_block = secretrs.query.tendermint.get_latest_block().await?;
    let latest_block_height = latest_block.header.height;
    info!("{:#?}", latest_block_height);

    Ok(())
}
