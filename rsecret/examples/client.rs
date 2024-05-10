#![allow(unused)]

use color_eyre::owo_colors::OwoColorize;
use rsecret::{CreateClientOptions, Result, SecretNetworkClient, TxOptions};

const GRPC_URL: &str = "http://grpc.testnet.secretsaturn.net:9090";
const CHAIN_ID: &str = "pulsar-3";

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    pretty_env_logger::init();

    let options = CreateClientOptions {
        url: GRPC_URL,
        chain_id: CHAIN_ID,
        ..Default::default()
    };
    let secretrs = SecretNetworkClient::connect(options).await?;
    println!(" {}", "SecretNetworkClient created".blue().bold());
    println!("{:#?}", secretrs.blue());

    let foo = secretrs
        .get_tx(
            // "95B29C83743756E7272C6F6117ADA63DE2E8B5C1434A6EEF994E167EE34EB050",
            "CED96D9A9AF074619374E81FECDAFBA4E2F58FC1A680322F0E4C5A05F5D3E8C6",
            None,
        )
        .await?;
    // println!("{:#?}", foo.unwrap().green());

    // let foo = secretrs.query.auth.params().await?;
    // println!("{:?}", foo);

    // let msg = MsgSend {
    //     from_address: "foo".parse()?,
    //     to_address: "bar".parse()?,
    //     amount: vec![],
    // };
    // let foo = secretrs.tx.bank.send(msg, TxOptions::default());

    // let mut secretrs_tx = TxSender::new(GRPC_URL).await?;
    // println!("{:#?}", secretrs_tx);

    // let msg = MsgSend {
    //     from_address: "foo".parse()?,
    //     to_address: "bar".parse()?,
    //     amount: vec![],
    // };
    // let foo = secretrs_tx.broadcast(vec![msg]);

    // let mut secretrs_query = Querier::new(GRPC_URL).await?;
    // println!("{:#?}", secretrs_query);
    //
    // let foo = secretrs_query.auth.params().await?;
    // println!("{:?}", foo);
    //
    // let bar = secretrs_query
    //     .bank
    //     .params(secretrs::proto::cosmos::bank::v1beta1::QueryParamsRequest {})
    //     .await?;
    // println!("{:?}", bar);

    Ok(())
}
