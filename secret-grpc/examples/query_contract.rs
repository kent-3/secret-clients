use color_eyre::eyre::Result;
use serde::{Deserialize, Serialize};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    color_eyre::install()?;

    let account = secret_grpc::Account::random();
    println!("{}", account.addr());

    let client = secret_grpc::SecretRPC::new()
        // .host("http://lcd.mainnet.secretsaturn.net")
        // .enclave_key("efdfbee583877e6d12c219695030a5bfb72e0a3abdc416655aa4a30c95a4446f")
        .host("http://lcd.testnet.secretsaturn.net")
        .enclave_key("e2b40597d50457d95290bdee480b8bc3400e9f40c2a5d69c9519f1fee2e24933")
        .chain_id("secret-4")
        .connect()
        .unwrap();

    let contract = secret_grpc::Contract::try_from_address_with_code_hash(
        // "secret1s09x2xvfd2lp2skgzm29w2xtena7s8fq98v852",
        "secret19gtpkk25r0c36gtlyrc6repd3q52ngmkpfszw3",
        "9a00ca4ad505e9be7e6e6dddf8d939b7ec7e9ac8e109c8681f10db9cacb36d42",
    )
    .unwrap();

    let ans: QueryAnswer = client
        .query_contract(
            &QueryMsg::MemberCode {
                address: "secret1r8w55329ukm802sdy0kr3jd5vq8ugtwt8h9djj".to_string(),
                key: "hola".to_string(),
            },
            &contract,
            &account,
        )
        .await?;

    match ans {
        QueryAnswer::MemberCode { code } => {
            println!("{code}");
        }
        QueryAnswer::ViewingKeyError { msg } => {
            println!("{msg}");
        }
        _ => {
            println!("Received a different kind of response");
        }
    }

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
