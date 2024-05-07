#![allow(unused)]

use rsecret::{CreateClientOptions, Result, SecretNetworkClient, TxOptions};

const GRPC_URL: &str = "http://grpc.testnet.secretsaturn.net:9090";
const CHAIN_ID: &str = "pulsar-3";

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    env_logger::init();

    let options = CreateClientOptions {
        url: GRPC_URL,
        chain_id: CHAIN_ID,
        ..Default::default()
    };
    let mut secretrs = SecretNetworkClient::connect(options).await?;
    // println!("{:#?}", secretrs);

    let foo = secretrs.query.auth.params().await?;
    println!("{:?}", foo);

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
