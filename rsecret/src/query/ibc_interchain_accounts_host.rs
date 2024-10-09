use crate::{Error, Result};
use ibc_proto::ibc::applications::interchain_accounts::host::v1::*;
use prost::Message;
pub use secretrs::{
    grpc_clients::IbcInterchainAccountsHostQueryClient,
    proto::cosmos::base::query::v1beta1::{PageRequest, PageResponse},
};
use tonic::{
    body::BoxBody,
    client::GrpcService,
    codegen::{Body, Bytes, StdError},
};
use tracing::{debug, info, warn};

#[derive(Debug, Clone)]
pub struct IbcInterchainAccountsHostQuerier<T> {
    inner: IbcInterchainAccountsHostQueryClient<T>,
}

#[cfg(not(target_arch = "wasm32"))]
impl IbcInterchainAccountsHostQuerier<::tonic::transport::Channel> {
    pub fn new(channel: ::tonic::transport::Channel) -> Self {
        let inner = IbcInterchainAccountsHostQueryClient::new(channel);
        Self { inner }
    }
}

#[cfg(target_arch = "wasm32")]
impl IbcInterchainAccountsHostQuerier<::tonic_web_wasm_client::Client> {
    pub fn new(client: ::tonic_web_wasm_client::Client) -> Self {
        let inner = IbcInterchainAccountsHostQueryClient::new(client);
        Self { inner }
    }
}

impl<T> IbcInterchainAccountsHostQuerier<T>
where
    T: GrpcService<BoxBody> + Clone,
    T::Error: Into<StdError>,
    T::ResponseBody: Body<Data = Bytes> + Send + 'static,
    <T::ResponseBody as Body>::Error: Into<StdError> + Send,
{
    /// Params queries all parameters of the ICA host submodule.
    pub async fn params(&self) -> Result<Params> {
        let request = QueryParamsRequest {};
        let response: ::tonic::Response<QueryParamsResponse> =
            self.inner.clone().params(request).await?;

        let params = response
            .into_inner()
            .params
            .ok_or(Error::MissingField { name: "params" })?;
        Ok(params)
    }
}
