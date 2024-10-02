use crate::{Error, Result};
use prost::Message;
pub use secretrs::{
    grpc_clients::MintQueryClient,
    proto::cosmos::{
        base::query::v1beta1::{PageRequest, PageResponse},
        mint::v1beta1::*,
    },
};
use tonic::{
    body::BoxBody,
    client::GrpcService,
    codegen::{Body, Bytes, StdError},
};
use tracing::{debug, info, warn};

#[derive(Debug, Clone)]
pub struct MintQuerier<T> {
    inner: MintQueryClient<T>,
}

#[cfg(not(target_arch = "wasm32"))]
impl MintQuerier<::tonic::transport::Channel> {
    pub fn new(channel: ::tonic::transport::Channel) -> Self {
        let inner = MintQueryClient::new(channel);
        Self { inner }
    }
}

#[cfg(target_arch = "wasm32")]
impl MintQuerier<::tonic_web_wasm_client::Client> {
    pub fn new(client: ::tonic_web_wasm_client::Client) -> Self {
        let inner = MintQueryClient::new(client);
        Self { inner }
    }
}

impl<T> MintQuerier<T>
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

        let params = response
            .into_inner()
            .params
            .ok_or(Error::MissingField { name: "params" })?;

        Ok(params)
    }

    // TODO: how do deal with the Vec<u8> response?
    pub async fn inflation(&self) -> Result<Vec<u8>> {
        let request = QueryInflationRequest {};
        let response: ::tonic::Response<QueryInflationResponse> =
            self.inner.clone().inflation(request).await?;

        let inflation = response.into_inner().inflation;

        Ok(inflation)
    }

    // TODO: how do deal with the Vec<u8> response?
    pub async fn annual_provisions(&self) -> Result<Vec<u8>> {
        let request = QueryAnnualProvisionsRequest {};
        let response: ::tonic::Response<QueryAnnualProvisionsResponse> =
            self.inner.clone().annual_provisions(request).await?;

        let annual_provisions = response.into_inner().annual_provisions;

        Ok(annual_provisions)
    }
}
