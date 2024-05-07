use super::{Error, Result};
use secretrs::clients::TendermintServiceClient;
use secretrs::proto::cosmos::base::tendermint::v1beta1::{
    AbciQueryRequest, AbciQueryResponse, GetBlockByHeightRequest, GetBlockByHeightResponse,
    GetLatestBlockRequest, GetLatestBlockResponse, GetLatestValidatorSetRequest,
    GetLatestValidatorSetResponse, GetNodeInfoRequest, GetNodeInfoResponse, GetSyncingRequest,
    GetSyncingResponse, GetValidatorSetByHeightRequest, GetValidatorSetByHeightResponse,
};
use tonic::codegen::{Body, Bytes, StdError};

#[derive(Debug, Clone)]
pub struct TendermintQuerier<T> {
    inner: TendermintServiceClient<T>,
}

#[cfg(not(target_arch = "wasm32"))]
impl TendermintQuerier<::tonic::transport::Channel> {
    pub fn new(channel: ::tonic::transport::Channel) -> Self {
        let inner = TendermintServiceClient::new(channel);
        Self { inner }
    }
}

#[cfg(target_arch = "wasm32")]
impl TendermintQuerier<::tonic_web_wasm_client::Client> {
    pub fn new(client: ::tonic_web_wasm_client::Client) -> Self {
        let inner = TendermintServiceClient::new(client);
        Self { inner }
    }
}

// TODO - add abstractions to make calling these methods easier? like I did with `get_tx`

impl<T> TendermintQuerier<T>
where
    T: tonic::client::GrpcService<tonic::body::BoxBody>,
    T::Error: Into<StdError>,
    T::ResponseBody: Body<Data = Bytes> + Send + 'static,
    <T::ResponseBody as Body>::Error: Into<StdError> + Send,
    T: Clone,
{
    pub async fn get_node_info(&self, request: GetNodeInfoRequest) -> Result<GetNodeInfoResponse> {
        self.inner
            .clone()
            .get_node_info(request)
            .await
            .map_err(Into::into)
            .map(::tonic::Response::into_inner)
    }
    pub async fn get_syncing(&self, request: GetSyncingRequest) -> Result<GetSyncingResponse> {
        self.inner
            .clone()
            .get_syncing(request)
            .await
            .map_err(Into::into)
            .map(::tonic::Response::into_inner)
    }
    pub async fn get_latest_block(
        &self,
        request: GetLatestBlockRequest,
    ) -> Result<GetLatestBlockResponse> {
        self.inner
            .clone()
            .get_latest_block(request)
            .await
            .map_err(Into::into)
            .map(::tonic::Response::into_inner)
    }
    pub async fn get_block_by_height(
        &self,
        request: GetBlockByHeightRequest,
    ) -> Result<GetBlockByHeightResponse> {
        self.inner
            .clone()
            .get_block_by_height(request)
            .await
            .map_err(Into::into)
            .map(::tonic::Response::into_inner)
    }
    pub async fn get_latest_validator_set(
        &self,
        request: GetLatestValidatorSetRequest,
    ) -> Result<GetLatestValidatorSetResponse> {
        self.inner
            .clone()
            .get_latest_validator_set(request)
            .await
            .map_err(Into::into)
            .map(::tonic::Response::into_inner)
    }
    pub async fn get_validator_set_by_height(
        &self,
        request: GetValidatorSetByHeightRequest,
    ) -> Result<GetValidatorSetByHeightResponse> {
        self.inner
            .clone()
            .get_validator_set_by_height(request)
            .await
            .map_err(Into::into)
            .map(::tonic::Response::into_inner)
    }
    pub async fn abci_query(&self, request: AbciQueryRequest) -> Result<AbciQueryResponse> {
        self.inner
            .clone()
            .abci_query(request)
            .await
            .map_err(Into::into)
            .map(::tonic::Response::into_inner)
    }
}
