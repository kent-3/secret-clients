#![allow(unused)]

// TODO - Add query methods (not sure if they exist... they are not in secretjs):
// ModuleAccounts, AccountAddressByID, AddressStringToBytes, AddressBytesToString, Bech32Prefix

use cosmrs::rpc::endpoint::abci_query::AbciQuery;
use cosmrs::Any;
use prost::Message;

use secretrs::clients::AuthQueryClient;

use ::cosmrs::proto::cosmos::auth::v1beta1::*;
use ::cosmrs::proto::cosmos::base::query::v1beta1::{PageRequest, PageResponse};
use ::cosmrs::proto::cosmos::vesting::v1beta1::{ContinuousVestingAccount, DelayedVestingAccount};

use super::{try_decode_any, try_decode_response};
use crate::{Error, Result};

#[derive(Clone, Debug)]
pub enum Account {
    BaseAccount(::cosmrs::auth::BaseAccount),
    ModuleAccount(::cosmrs::auth::ModuleAccount),
    ContinuousVestingAccount(::cosmrs::vesting::ContinuousVestingAccount),
    DelayedVestingAccount(::cosmrs::vesting::DelayedVestingAccount),
}

#[cfg(not(target_arch = "wasm32"))]
pub struct AuthQuerier {
    inner: AuthQueryClient<::tonic::transport::Channel>,
}

#[cfg(not(target_arch = "wasm32"))]
impl AuthQuerier {
    pub async fn new(url: impl Into<String>) -> Result<Self> {
        let url = url.into();
        let inner = query_client::QueryClient::connect(url).await.unwrap();

        Ok(Self { inner })
    }
}

#[cfg(target_arch = "wasm32")]
pub struct AuthQuerier {
    inner: AuthQueryClient<::tonic_web_wasm_client::Client>,
}

#[cfg(target_arch = "wasm32")]
impl AuthQuerier {
    pub async fn new(base_url: impl Into<String>) -> Result<Self> {
        let base_url = base_url.into();
        let web_wasm_client = ::tonic_web_wasm_client::Client::new(base_url);
        let inner = query_client::QueryClient::new(web_wasm_client);

        Ok(Self { inner })
    }
}

impl AuthQuerier {
    pub async fn account(&mut self, address: impl Into<String>) -> Result<Account> {
        let address = address.into();
        let msg = QueryAccountRequest { address };
        let response: QueryAccountResponse = self.inner.account(msg).await.unwrap().into_inner();

        let any = response.clone().account.unwrap();

        match any.type_url.as_str() {
            "/cosmos.auth.v1beta1.BaseAccount" => {
                let account: BaseAccount = any.to_msg()?;
                Ok(Account::BaseAccount(account.try_into()?))
            }
            "/cosmos.auth.v1beta1.ModuleAccount" => {
                let account: ModuleAccount = any.to_msg()?;
                Ok(Account::ModuleAccount(account.try_into()?))
            }
            // trait 'Name' is not implemented for these
            "/cosmos.vesting.v1beta1.ContinuousVestingAccount" => {
                let account = try_decode_any::<ContinuousVestingAccount>(any)?;
                Ok(Account::ContinuousVestingAccount(account.try_into()?))
            }
            "/cosmos.vesting.v1beta1.DelayedVestingAccount" => {
                let account = try_decode_any::<DelayedVestingAccount>(any)?;
                Ok(Account::DelayedVestingAccount(account.try_into()?))
            }
            _ => Err(Error::AbciQuery(format!(
                "unexpected type_url: {}",
                any.type_url
            ))),
        }
    }

    pub async fn accounts(
        &mut self,
        pagination: Option<PageRequest>,
    ) -> Result<MyQueryAccountsResponse> {
        let msg = QueryAccountsRequest { pagination };
        let response: QueryAccountsResponse = self.inner.accounts(msg).await.unwrap().into_inner();

        response.try_into()
    }

    pub async fn params(&mut self) -> Result<QueryParamsResponse> {
        let msg = QueryParamsRequest {};
        let response: QueryParamsResponse = self.inner.params(msg).await.unwrap().into_inner();

        Ok(response)
    }

    // TODO - decode the Any. return a ModuleAccount?
    pub async fn module_account_by_name(
        &mut self,
        name: impl Into<String>,
    ) -> Result<QueryModuleAccountByNameResponse> {
        let name = name.into();
        let msg = QueryModuleAccountByNameRequest { name };
        let response = self.inner.module_account_by_name(msg).await.unwrap();
        // .and_then(|res| {
        //     res.account
        //         .ok_or(Error::AbciQuery("empty account".to_string()))
        // })
        // .and_then(|any| any.to_msg::<ModuleAccount>().map_err(Error::from))
        // .and_then(|acc| acc.try_into().map_err(Error::from))

        Ok(response.into_inner())
    }
}

// impl crate::Client {
//     // TODO - decide on returning Account vs QueryAccountResponse
//     pub async fn auth_account(&self, address: impl Into<String>) -> Result<QueryAccountResponse> {
//         let address = address.into();
//
//         let path = "/cosmos.auth.v1beta1.Query/Account";
//         let msg = QueryAccountRequest { address };
//
//         self.query_with_msg(path, msg)
//             .await
//             .and_then(try_decode_response::<QueryAccountResponse>)
//
//         // let any = self
//         //     .query_with_msg(path, msg)
//         //     .await
//         //     .and_then(try_decode_response::<QueryAccountResponse>);
//         //     .and_then(|res| {
//         //         res.account
//         //             .ok_or(Error::AbciQuery("no account".to_string()))
//         //     })?;
//         //
//         // match any.type_url.as_str() {
//         //     "/cosmos.auth.v1beta1.BaseAccount" => {
//         //         let account: BaseAccount = any.to_msg()?;
//         //         Ok(Account::BaseAccount(account.try_into()?))
//         //     }
//         //     "/cosmos.auth.v1beta1.ModuleAccount" => {
//         //         let account: ModuleAccount = any.to_msg()?;
//         //         Ok(Account::ModuleAccount(account.try_into()?))
//         //     }
//         //     // trait 'Name' is not implemented for these
//         //     "/cosmos.vesting.v1beta1.ContinuousVestingAccount" => {
//         //         let account = try_decode_any::<ContinuousVestingAccount>(any)?;
//         //         Ok(Account::ContinuousVestingAccount(account.try_into()?))
//         //     }
//         //     "/cosmos.vesting.v1beta1.DelayedVestingAccount" => {
//         //         let account = try_decode_any::<DelayedVestingAccount>(any)?;
//         //         Ok(Account::DelayedVestingAccount(account.try_into()?))
//         //     }
//         //     _ => Err(Error::AbciQuery(format!(
//         //         "unexpected type_url: {}",
//         //         any.type_url
//         //     ))),
//         // }
//     }
//
//     // TODO - more work needed here to handle the response and pagination...
//     pub async fn auth_accounts(
//         &self,
//         pagination: Option<PageRequest>,
//     ) -> Result<QueryAccountsResponse> {
//         let path = "/cosmos.auth.v1beta1.Query/Accounts";
//         let msg = QueryAccountsRequest { pagination };
//
//         self.query_with_msg(path, msg)
//             .await
//             .and_then(try_decode_response::<QueryAccountsResponse>)
//     }
//
//     pub async fn auth_params(&self) -> Result<QueryParamsResponse> {
//         let path = "/cosmos.auth.v1beta1.Query/Params";
//         let msg = QueryParamsRequest {};
//
//         self.query_with_msg(path, msg)
//             .await
//             .and_then(try_decode_response::<QueryParamsResponse>)
//         // .and_then(|x| x.params.ok_or(Error::AbciQuery("empty params".to_string())))
//     }
//
//     pub async fn auth_module_account_by_name(
//         &self,
//         name: impl Into<String>,
//     ) -> Result<QueryModuleAccountByNameResponse> {
//         let name = name.into();
//
//         let path = "/cosmos.auth.v1beta1.Query/ModuleAccountByName";
//         let msg = QueryModuleAccountByNameRequest { name };
//
//         self.query_with_msg(path, msg)
//             .await
//             .and_then(try_decode_response::<QueryModuleAccountByNameResponse>)
//         // .and_then(|res| {
//         //     res.account
//         //         .ok_or(Error::AbciQuery("empty account".to_string()))
//         // })
//         // .and_then(|any| any.to_msg::<ModuleAccount>().map_err(Error::from))
//         // .and_then(|acc| acc.try_into().map_err(Error::from))
//     }
// }

// TODO - move this to a different location... probably in the secretrs crate

#[derive(Clone, Debug)]
pub struct MyQueryAccountsResponse {
    pub accounts: Vec<Account>,
    // TODO - convert the `proto::...::PageResponse` to `cosmrs::query::PageResponse`
    pub pagination: Option<PageResponse>,
}

impl TryFrom<::cosmrs::proto::cosmos::auth::v1beta1::QueryAccountsResponse>
    for MyQueryAccountsResponse
{
    type Error = Error;

    fn try_from(
        value: ::cosmrs::proto::cosmos::auth::v1beta1::QueryAccountsResponse,
    ) -> Result<Self> {
        let accounts = value
            .accounts
            .into_iter()
            .map(|any| match any.type_url.as_str() {
                "/cosmos.auth.v1beta1.BaseAccount" => {
                    let account: BaseAccount = any.to_msg()?;
                    Ok(Account::BaseAccount(account.try_into()?))
                }
                "/cosmos.auth.v1beta1.ModuleAccount" => {
                    let account: ModuleAccount = any.to_msg()?;
                    Ok(Account::ModuleAccount(account.try_into()?))
                }
                "/cosmos.vesting.v1beta1.ContinuousVestingAccount" => {
                    let account = try_decode_any::<ContinuousVestingAccount>(any)?;
                    Ok(Account::ContinuousVestingAccount(account.try_into()?))
                }
                "/cosmos.vesting.v1beta1.DelayedVestingAccount" => {
                    let account = try_decode_any::<DelayedVestingAccount>(any)?;
                    Ok(Account::DelayedVestingAccount(account.try_into()?))
                }
                _ => Err(Error::AbciQuery(format!(
                    "unexpected type_url: {}",
                    any.type_url
                ))),
            })
            .collect::<Result<Vec<_>>>()?;

        let pagination = value.pagination;

        Ok(MyQueryAccountsResponse {
            accounts,
            pagination,
        })
    }
}
