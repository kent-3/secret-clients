#[allow(unused)]
use log::{debug, error, info, warn};

use secret_grpc::client::SecretNetworkClient;

use color_eyre::Result;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    std::env::set_var("RUST_LOG", "info");
    color_eyre::install()?;
    pretty_env_logger::init();

    // Returns a `secret_grpc::Client`
    // let client = secret_grpc::SecretRPC::new()
    //     .host("http://lcd.testnet.secretsaturn.net")
    //     .enclave_key("e2b40597d50457d95290bdee480b8bc3400e9f40c2a5d69c9519f1fee2e24933")
    //     .chain_id("secret-4")
    //     .connect()?;

    // A single item page used throughout for brevity
    use ::cosmrs::proto::cosmos::base::query::v1beta1::PageRequest;
    let one_page = Some(PageRequest {
        key: vec![],
        offset: 0,
        limit: 1,
        count_total: true,
        reverse: false,
    });

    let mut secretrs = SecretNetworkClient::new("http://grpc.testnet.secretsaturn.net:9090").await;

    info!(target: "auth", "Testing 'auth' queries");

    let resp = secretrs
        .auth
        .account(secret_grpc::account::a().addr())
        .await
        .unwrap();
    info!(target: "auth", "{resp:?}");

    // There are 4 different possible types of accounts associated with an address
    // use secret_grpc::query::auth::Account;
    // match resp {
    //     Account::BaseAccount(base) => {
    //         info!(target: "auth", "{:?}", base)
    //     }
    //     Account::ModuleAccount(module) => {
    //         info!(target: "auth", "{:?}", module)
    //     }
    //     Account::ContinuousVestingAccount(continuous) => {
    //         info!(target: "auth", "{:?}", continuous)
    //     }
    //     Account::DelayedVestingAccount(delayed) => {
    //         info!(target: "auth", "{:?}", delayed)
    //     }
    // };

    let resp = secretrs.auth.accounts(one_page).await.unwrap();
    info!(target: "auth", "{resp:?}");

    let resp = secretrs.auth.params().await?;
    info!(target: "auth", "{resp:?}");

    let resp = secretrs.auth.module_account_by_name("gov").await?;
    info!(target: "auth", "{resp:?}");

    // Bank

    // let resp = client
    //     .bank_balance(secret_grpc::account::a().addr().to_string(), "uscrt")
    //     .await?;
    // info!(target: "bank", "{resp:?}");
    //
    // let resp = client
    //     .bank_all_balances(
    //         secret_grpc::account::a().addr().to_string(),
    //         one_page.clone(),
    //     )
    //     .await?;
    // info!(target: "bank", "{resp:?}");
    //
    // let resp = client.bank_params().await?;
    // info!(target: "bank", "{resp:?}");
    //
    // let resp = client.bank_total_supply(one_page).await?;
    // info!(target: "bank", "{resp:?}");

    // Compute

    // let req = ::tonic::Request::new(QueryByCodeIdRequest { code_id: 1u64 });
    // let resp = secretrs
    //     .compute
    //     .inner
    //     .code(req)
    //     .await
    //     .unwrap()
    //     .into_inner()
    //     .code_info
    //     .unwrap();
    // info!(target: "compute", "{resp:?}");
    //
    // let resp = secretrs
    //     .compute
    //     .code_hash_by_code_id(1u64)
    //     .await
    //     .unwrap()
    //     .code_hash;
    // info!(target: "compute", "{resp:?}");

    Ok(())
}
