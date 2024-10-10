use crate::{Error, Result};
use prost::Message;
pub use secretrs::{
    grpc_clients::AuthQueryClient,
    proto::cosmos::auth::v1beta1::{
        AddressBytesToStringRequest, AddressBytesToStringResponse, AddressStringToBytesRequest,
        AddressStringToBytesResponse, BaseAccount, ModuleAccount, Params,
        QueryAccountAddressByIdRequest, QueryAccountAddressByIdResponse, QueryAccountRequest,
        QueryAccountResponse, QueryAccountsRequest, QueryAccountsResponse,
        QueryModuleAccountByNameRequest, QueryModuleAccountByNameResponse,
        QueryModuleAccountsRequest, QueryModuleAccountsResponse, QueryParamsRequest,
        QueryParamsResponse,
    },
    proto::cosmos::vesting::v1beta1::{ContinuousVestingAccount, DelayedVestingAccount},
    query::PageRequest,
};
use tonic::{
    body::BoxBody,
    client::GrpcService,
    codegen::{Body, Bytes, StdError},
};
use tracing::{debug, info};

#[derive(Debug, Clone)]
pub struct AuthQuerier<T> {
    inner: AuthQueryClient<T>,
}

#[cfg(not(target_arch = "wasm32"))]
impl AuthQuerier<::tonic::transport::Channel> {
    pub fn new(channel: ::tonic::transport::Channel) -> Self {
        let inner = AuthQueryClient::new(channel);
        Self { inner }
    }
}

#[cfg(target_arch = "wasm32")]
impl AuthQuerier<::tonic_web_wasm_client::Client> {
    pub fn new(client: ::tonic_web_wasm_client::Client) -> Self {
        let inner = AuthQueryClient::new(client);
        Self { inner }
    }
}

// TODO - add ability to set headers of the request (especially 'x-cosmos-block-height')

impl<T> AuthQuerier<T>
where
    T: GrpcService<BoxBody> + Clone,
    T::Error: Into<StdError>,
    T::ResponseBody: Body<Data = Bytes> + Send + 'static,
    <T::ResponseBody as Body>::Error: Into<StdError> + Send,
{
    pub async fn params(&self) -> Result<Params> {
        let request = QueryParamsRequest {};
        let response: ::tonic::Response<QueryParamsResponse> =
            self.inner.clone().params(request).await?;

        response
            .into_inner()
            .params
            .ok_or(Error::MissingField { name: "params" })

        // example showing how to add block height headers to a request:
        //
        // let mut request = ::tonic::Request::new(request);
        // request
        //     .metadata_mut()
        //     .insert("x-cosmos-block-height", "4739000".parse().unwrap());
        //
        // let response: ::tonic::Response<QueryParamsResponse> =
        //     self.inner.clone().params(request).await?;
        //
        // let (metadata, response, _) = response.into_parts();
        //
        // let http_headers = metadata.into_headers();
        // let block_height = http_headers.get("x-cosmos-block-height");
        //
        // log::debug!("x-cosmos-block-height: {:?}", block_height);
        //
        // response.params.ok_or("params empty".into())
    }

    pub async fn accounts(&self, pagination: Option<PageRequest>) -> Result<QueryAccountsResponse> {
        let pagination = pagination.map(Into::into);
        let request = QueryAccountsRequest { pagination };
        let response: ::tonic::Response<QueryAccountsResponse> =
            self.inner.clone().accounts(request).await?;

        Ok(response.into_inner())
    }

    // This is the most important auth query!
    // using a custom "Account" enum to cover all 4 possible account types
    pub async fn account(&self, address: impl Into<String>) -> Result<Option<Account>> {
        let address = address.into();
        let request = QueryAccountRequest { address };
        let response: ::tonic::Response<QueryAccountResponse> =
            self.inner.clone().account(request).await?;

        let (metadata, response, _) = response.into_parts();

        let http_headers = metadata.into_headers();
        let block_height = http_headers.get("x-cosmos-block-height");

        debug!("x-cosmos-block-height: {:?}", block_height);

        if let Some(any) = response.account {
            match any.type_url.as_str() {
                "/cosmos.auth.v1beta1.BaseAccount" => {
                    let account: BaseAccount = any.to_msg()?;
                    Ok(Some(Account::BaseAccount(account.try_into()?)))
                }
                "/cosmos.auth.v1beta1.ModuleAccount" => {
                    let account: ModuleAccount = any.to_msg()?;
                    Ok(Some(Account::ModuleAccount(account.try_into()?)))
                }
                // trait 'Name' is not implemented for these
                "/cosmos.vesting.v1beta1.ContinuousVestingAccount" => {
                    let account =
                        <ContinuousVestingAccount as Message>::decode(any.value.as_ref())?;
                    Ok(Some(Account::ContinuousVestingAccount(account.try_into()?)))
                }
                "/cosmos.vesting.v1beta1.DelayedVestingAccount" => {
                    let account = <DelayedVestingAccount as Message>::decode(any.value.as_ref())?;
                    Ok(Some(Account::DelayedVestingAccount(account.try_into()?)))
                }
                _ => Err(Error::InvalidAny {
                    type_url: any.type_url,
                }),
            }
        } else {
            Ok(None)
        }
    }

    // TODO: use account_id instead of id? (check what Secret actually uses)
    pub async fn account_address_by_id(&self, id: impl Into<i64>) -> Result<String> {
        let id = id.into();
        let account_id = 0u64;

        let request = QueryAccountAddressByIdRequest { id, account_id };
        let response: ::tonic::Response<QueryAccountAddressByIdResponse> =
            self.inner.clone().account_address_by_id(request).await?;

        Ok(response.into_inner().account_address)
    }

    pub async fn module_accounts(&self) -> Result<Vec<::secretrs::auth::ModuleAccount>> {
        unimplemented!("unknown method ModuleAccounts for service cosmos.auth.v1beta1.Query");

        let request = QueryModuleAccountsRequest {};
        let response: ::tonic::Response<QueryModuleAccountsResponse> =
            self.inner.clone().module_accounts(request).await?;

        // convert `Any` to proto::cosmos::auth::v1beta1::ModuleAccount to secretrs::auth::ModuleAccount
        response
            .into_inner()
            .accounts
            .iter()
            .map(|any| Ok(any.to_msg::<ModuleAccount>()?.try_into()?))
            .collect::<Result<Vec<::secretrs::auth::ModuleAccount>>>()
    }

    pub async fn module_account_by_name(
        &self,
        name: impl Into<String>,
    ) -> Result<Option<::secretrs::auth::ModuleAccount>> {
        let name = name.into();
        let request = QueryModuleAccountByNameRequest { name };
        let response: ::tonic::Response<QueryModuleAccountByNameResponse> =
            self.inner.clone().module_account_by_name(request).await?;

        // convert `Any` to proto::cosmos::auth::v1beta1::ModuleAccount to secretrs::auth::ModuleAccount
        response
            .into_inner()
            .account
            .map(|any| Ok(any.to_msg::<ModuleAccount>()?.try_into()?))
            .transpose()
    }

    pub async fn address_string_to_bytes(
        &self,
        address_string: impl Into<String>,
    ) -> Result<Vec<u8>> {
        let address_string = address_string.into();
        let request = AddressStringToBytesRequest { address_string };
        let response: ::tonic::Response<AddressStringToBytesResponse> =
            self.inner.clone().address_string_to_bytes(request).await?;

        Ok(response.into_inner().address_bytes)
    }

    pub async fn address_bytes_to_string(&self, address_bytes: Vec<u8>) -> Result<String> {
        let request = AddressBytesToStringRequest { address_bytes };
        let response: ::tonic::Response<AddressBytesToStringResponse> =
            self.inner.clone().address_bytes_to_string(request).await?;

        Ok(response.into_inner().address_string)
    }
}

#[derive(Clone, Debug)]
pub enum Account {
    BaseAccount(::secretrs::auth::BaseAccount),
    ModuleAccount(::secretrs::auth::ModuleAccount),
    ContinuousVestingAccount(::secretrs::vesting::ContinuousVestingAccount),
    DelayedVestingAccount(::secretrs::vesting::DelayedVestingAccount),
}
