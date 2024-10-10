use crate::{Error, Result};
use prost::Message;
pub use secretrs::{
    grpc_clients::ParamsQueryClient,
    proto::cosmos::{
        base::query::v1beta1::{PageRequest, PageResponse},
        params::v1beta1::*,
    },
};
use tonic::{
    body::BoxBody,
    client::GrpcService,
    codegen::{Body, Bytes, StdError},
};
use tracing::{debug, info, warn};

#[derive(Debug, Clone)]
pub struct ParamsQuerier<T> {
    inner: ParamsQueryClient<T>,
}

#[cfg(not(target_arch = "wasm32"))]
impl ParamsQuerier<::tonic::transport::Channel> {
    pub fn new(channel: ::tonic::transport::Channel) -> Self {
        let inner = ParamsQueryClient::new(channel);
        Self { inner }
    }
}

#[cfg(target_arch = "wasm32")]
impl ParamsQuerier<::tonic_web_wasm_client::Client> {
    pub fn new(client: ::tonic_web_wasm_client::Client) -> Self {
        let inner = ParamsQueryClient::new(client);
        Self { inner }
    }
}

impl<T> ParamsQuerier<T>
where
    T: GrpcService<BoxBody> + Clone,
    T::Error: Into<StdError>,
    T::ResponseBody: Body<Data = Bytes> + Send + 'static,
    <T::ResponseBody as Body>::Error: Into<StdError> + Send,
{
    pub async fn params(
        &self,
        subspace: impl Into<String>,
        key: impl Into<String>,
    ) -> Result<ParamChange> {
        let subspace = subspace.into();
        let key = key.into();

        let request = QueryParamsRequest { subspace, key };
        let response = self.inner.clone().params(request).await?;

        let param = response
            .into_inner()
            .param
            .ok_or(Error::MissingField { name: "param" })?;

        Ok(param)
    }

    /// Since: cosmos-sdk 0.46
    pub async fn subspaces(&self) -> Result<QuerySubspacesResponse> {
        let req = QuerySubspacesRequest {};
        unimplemented!()
    }
}
