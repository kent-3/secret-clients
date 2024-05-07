use color_eyre::{eyre::Result, owo_colors::OwoColorize};
use secret_grpc::TendermintClient;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    color_eyre::install()?;

    let client = secret_grpc::SecretRPC::new()
        .host("http://lcd.testnet.secretsaturn.net")
        .enclave_key("e2b40597d50457d95290bdee480b8bc3400e9f40c2a5d69c9519f1fee2e24933")
        .chain_id("secret-4")
        .connect()?;

    println!("\n{}", "client.query_uscrt_balance(account)".bold());
    let account = secret_grpc::account::a();
    let balance = client.query_uscrt_balance(account.addr().as_str()).await?;
    println!("\n{}", balance.green());

    println!("\n{}", "client.rpc.latest_block()".bold());
    let response = client.rpc.latest_block().await?;
    // println!("{}", serde_json::to_string_pretty(&response)?);
    let latest_block_height = response.block.header.height;
    println!("{}", latest_block_height.magenta());

    println!("\n{}", "client.rpc.block(height)".bold());
    let previous_block_height = latest_block_height.value() - 5u64;
    let response = client.rpc.block(previous_block_height as u32).await?;
    let previous_block_height = response.block.header.height;
    println!("{}", previous_block_height.magenta());

    // println!("\n{}", "get_latest_validator_set".bold());
    // let resp = get_validator_set_by_height(
    //     &configuration,
    //     GetValidatorSetByHeightParams {
    //         height: future_block.clone(),
    //         ..GetValidatorSetByHeightParams::default()
    //     },
    // )
    // .await;
    // println!("{}", resp.unwrap_err().bright_yellow());
    //
    // println!("\n{}", "contracts_by_code_id".bold());
    // let resp = contracts_by_code_id(
    //     &configuration,
    //     ContractsByCodeIdParams {
    //         code_id: "99999999999".to_string(),
    //     },
    // )
    // .await;
    // println!("{}", resp.unwrap_err().bright_yellow());

    Ok(())
}
