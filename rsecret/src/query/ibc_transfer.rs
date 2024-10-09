use crate::{Error, Result};
use ibc_proto::ibc::applications::transfer::v1::*;
use prost::Message;
pub use secretrs::{
    grpc_clients::IbcTransferQueryClient,
    proto::cosmos::base::query::v1beta1::{PageRequest, PageResponse},
};
use tonic::{
    body::BoxBody,
    client::GrpcService,
    codegen::{Body, Bytes, StdError},
};
use tracing::{debug, info, warn};

#[derive(Debug, Clone)]
pub struct IbcTransferQuerier<T> {
    inner: IbcTransferQueryClient<T>,
}

#[cfg(not(target_arch = "wasm32"))]
impl IbcTransferQuerier<::tonic::transport::Channel> {
    pub fn new(channel: ::tonic::transport::Channel) -> Self {
        let inner = IbcTransferQueryClient::new(channel);
        Self { inner }
    }
}

#[cfg(target_arch = "wasm32")]
impl IbcTransferQuerier<::tonic_web_wasm_client::Client> {
    pub fn new(client: ::tonic_web_wasm_client::Client) -> Self {
        let inner = IbcTransferQueryClient::new(client);
        Self { inner }
    }
}

impl<T> IbcTransferQuerier<T>
where
    T: GrpcService<BoxBody> + Clone,
    T::Error: Into<StdError>,
    T::ResponseBody: Body<Data = Bytes> + Send + 'static,
    <T::ResponseBody as Body>::Error: Into<StdError> + Send,
{
    /// DenomTrace queries a denomination trace information.
    pub async fn denom_trace(
        &mut self,
        request: impl tonic::IntoRequest<QueryDenomTraceRequest>,
    ) -> Result<QueryDenomTraceResponse> {
        todo!()
    }

    /// DenomTraces queries all denomination traces.
    pub async fn denom_traces(
        &mut self,
        request: impl tonic::IntoRequest<QueryDenomTracesRequest>,
    ) -> Result<QueryDenomTracesResponse> {
        todo!()
    }

    /// Params queries all parameters of the ibc-transfer module.
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

    /// DenomHash queries a denomination hash information.
    pub async fn denom_hash(
        &mut self,
        request: impl tonic::IntoRequest<QueryDenomHashRequest>,
    ) -> Result<QueryDenomHashResponse> {
        todo!()
    }
}
