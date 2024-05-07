use secret_grpc::Contract;

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum QueryMsg {
    TokenInfo {},
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
pub enum QueryAnswer {
    TokenInfo {
        name: String,
        symbol: String,
        decimals: u8,
        total_supply: Option<cosmwasm_std::Uint128>,
    },
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let client = secret_grpc::SecretRPC::new()
        .host("http://rpc.testnet.secretsaturn.net")
        .enclave_key("e2b40597d50457d95290bdee480b8bc3400e9f40c2a5d69c9519f1fee2e24933")
        .connect()
        .unwrap();

    let contract = Contract::try_from_address_with_code_hash(
        "secret1gvn6eap7xgsf9kydgmvpqwzkru2zj35ar2vncj",
        "c74bc4b0406507257ed033caa922272023ab013b0c74330efc16569528fa34fe",
    )
    .unwrap();

    let ans: QueryAnswer = client
        .query_contract(
            &QueryMsg::TokenInfo {},
            &contract,
            &secret_grpc::account::a(),
        )
        .await
        .unwrap();

    println!("{ans:#?}");
}
