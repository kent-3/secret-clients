#![allow(unused)]

use color_eyre::owo_colors::OwoColorize;
use rsecret::{CreateClientOptions, Result, SecretNetworkClient, TxOptions};
use secretrs::compute::ContractInfo;
use secretrs::proto::cosmos::base::tendermint::v1beta1::{
    GetBlockByHeightResponse, GetLatestBlockResponse, GetLatestValidatorSetResponse,
    GetNodeInfoResponse, GetSyncingResponse, GetValidatorSetByHeightResponse,
};
use secretrs::proto::secret::compute::v1beta1::{
    QueryByCodeIdRequest, QueryCodeResponse, QueryCodesResponse, QueryContractHistoryResponse,
    QueryContractInfoResponse, QueryContractLabelResponse, QuerySecretContractRequest,
};
use secretrs::{proto::cosmos::tx::v1beta1::OrderBy, tendermint::Block};
use serde::Deserialize;
use serde::Serialize;

const GRPC_URL: &str = "http://grpc.testnet.secretsaturn.net:9090";
const CHAIN_ID: &str = "pulsar-3";

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    pretty_env_logger::init();

    let contract_address = "secret19gtpkk25r0c36gtlyrc6repd3q52ngmkpfszw3";
    let code_hash = "9a00ca4ad505e9be7e6e6dddf8d939b7ec7e9ac8e109c8681f10db9cacb36d42";
    let query = QueryMsg::TokenInfo {};

    let options = CreateClientOptions {
        url: GRPC_URL,
        chain_id: CHAIN_ID,
        ..Default::default()
    };

    let secretrs = SecretNetworkClient::connect(options).await?;
    println!(" {}", "SecretNetworkClient created".blue().bold());
    // println!("{:#?}", secretrs.blue());

    // TODO: figure out a unified approach for the response types.
    // For example, this GetLatestBlockResponse is different from the protobuf one.
    // (because I made it that way - it uses the extended types from cosmrs)
    // I could have a `try_into` for every response type, but that's a lot of work!
    let latest_block = secretrs.query.tendermint.get_latest_block().await?;
    // println!(" {:#?}", latest_block.yellow());
    let latest_block_height = latest_block.block.header.height;
    println!(" Latest block: {:#?}", latest_block_height.yellow());

    // it works!
    // let secret_contract_response = secretrs
    //     .query
    //     .compute
    //     .query_secret_contract(contract_address, code_hash, query)
    //     .await?;
    // println!(" {}", secret_contract_response.bright_white());

    // it works!
    // let deserialized: QueryAnswer = serde_json::from_str(&secret_contract_response)?;
    // println!(" {:?}", deserialized.magenta());

    // it works!
    // let QueryContractInfoResponse {
    //     contract_address,
    //     contract_info,
    // } = secretrs
    //     .query
    //     .compute
    //     .contract_info(contract_address)
    //     .await?;
    // let contract_info = ContractInfo::try_from(contract_info.unwrap())?;
    // println!(" {:?}", contract_address.bright_white());
    // println!(" {:?}", contract_info.bright_white());

    // it works!
    // let GetBlockByHeightResponse {
    //     block_id,
    //     block,
    //     sdk_block,
    // } = secretrs
    //     .query
    //     .tendermint
    //     .get_block_by_height(4828567u32)
    //     .await?;
    // println!(" {:#?}", block_id.bright_green());
    // println!(" {:#?}", block.green());
    // println!(" {:#?}", sdk_block.bright_green());

    // it works!
    // let GetNodeInfoResponse {
    //     default_node_info,
    //     application_version,
    // } = secretrs.query.tendermint.get_node_info().await?;
    // println!(" {:#?}", default_node_info.bright_blue());
    // println!(" {:#?}", application_version.blue());

    // it works!
    // let GetSyncingResponse { syncing } = secretrs.query.tendermint.get_syncing().await?;
    // println!(" {:#?}", syncing.magenta());

    // it works!
    // let foo = secretrs
    //     .get_tx(
    //         // "95B29C83743756E7272C6F6117ADA63DE2E8B5C1434A6EEF994E167EE34EB050",
    //         "CED96D9A9AF074619374E81FECDAFBA4E2F58FC1A680322F0E4C5A05F5D3E8C6",
    //         None,
    //     )
    //     .await?;
    // println!("{:#?}", foo.unwrap().green());

    // it works!
    // let bar = secretrs
    //     .txs_query(
    //         // "tx.hash='CED96D9A9AF074619374E81FECDAFBA4E2F58FC1A680322F0E4C5A05F5D3E8C6'",
    //         "tx.height=4825000",
    //         None,
    //         None,
    //         OrderBy::Asc,
    //     )
    //     .await?;
    // println!("{:#?}", bar.unwrap().green());

    // let foo = secretrs.query.auth.params().await?;
    // println!("{:?}", foo);

    // let msg = MsgSend {
    //     from_address: "foo".parse()?,
    //     to_address: "bar".parse()?,
    //     amount: vec![],
    // };
    // let foo = secretrs.tx.bank.send(msg, TxOptions::default());

    Ok(())
}

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
