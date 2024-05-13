#![allow(unused)]

use rsecret::{CreateClientOptions, Result, SecretNetworkClient, TxOptions};
use secretrs::{
    compute::ContractInfo,
    proto::{
        cosmos::{
            base::tendermint::v1beta1::{
                GetBlockByHeightResponse, GetLatestBlockResponse, GetLatestValidatorSetResponse,
                GetNodeInfoResponse, GetSyncingResponse, GetValidatorSetByHeightResponse,
            },
            staking::v1beta1::BondStatus,
            tx::v1beta1::OrderBy,
        },
        secret::compute::v1beta1::{
            QueryByCodeIdRequest, QueryCodeResponse, QueryCodesResponse,
            QueryContractHistoryResponse, QueryContractInfoResponse, QueryContractLabelResponse,
            QuerySecretContractRequest,
        },
    },
    tendermint::Block,
};
use serde::{Deserialize, Serialize};
use tracing::{debug, info, trace};
use tracing_subscriber::{fmt::format::DefaultFields, EnvFilter};

const GRPC_URL: &str = "http://grpc.testnet.secretsaturn.net:9090";
const CHAIN_ID: &str = "pulsar-3";
// const GRPC_URL: &str = "http://grpc.mainnet.secretsaturn.net:9090";
// const CHAIN_ID: &str = "secret-4";

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    ::tracing_subscriber::fmt()
        .pretty()
        .without_time()
        .with_line_number(false)
        .with_file(false)
        .with_env_filter(EnvFilter::new(
            "debug,rsecret=debug,hyper=debug,h2=debug,tower=debug,tonic=debug",
        ))
        .init();

    let contract_address = "secret19gtpkk25r0c36gtlyrc6repd3q52ngmkpfszw3";
    let code_hash = "9a00ca4ad505e9be7e6e6dddf8d939b7ec7e9ac8e109c8681f10db9cacb36d42";
    let query = QueryMsg::TokenInfo {};

    let options = CreateClientOptions {
        url: GRPC_URL,
        chain_id: CHAIN_ID,
        ..Default::default()
    };

    let secretrs = SecretNetworkClient::connect(options).await?;
    info!("SecretNetworkClient created");
    // debug!("{:#?}", secretrs);

    let latest_block = secretrs.query.tendermint.get_latest_block().await?;
    // debug!("{:?}", latest_block);
    let latest_block_height = latest_block.header.height;
    info!("{:?}", latest_block_height);

    use secretrs::proto::cosmos::base::query::v1beta1::PageRequest;
    let pagination = Some(PageRequest {
        key: vec![],
        offset: 0,
        limit: 10,
        count_total: true,
        reverse: false,
    });

    // let validators = secretrs
    //     .query
    //     .staking
    //     .validators(BondStatus::Bonded, pagination)
    //     .await?;
    let validators = secretrs.all_validators().await?;
    let validator_monikers: Vec<String> = validators
        .into_iter()
        .map(|v| v.description.unwrap_or_default().moniker)
        .collect();
    info!("{:?}", validator_monikers);

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
