use crate::{Error, Result};
use secretrs::grpc_clients::TendermintServiceClient;
use secretrs::proto::cosmos::base::query::v1beta1::PageRequest;
pub use secretrs::proto::cosmos::base::tendermint::v1beta1::{
    AbciQueryRequest, AbciQueryResponse, GetBlockByHeightRequest, GetBlockByHeightResponse,
    GetLatestBlockRequest, GetLatestBlockResponse, GetLatestValidatorSetRequest,
    GetLatestValidatorSetResponse, GetNodeInfoRequest, GetNodeInfoResponse, GetSyncingRequest,
    GetSyncingResponse, GetValidatorSetByHeightRequest, GetValidatorSetByHeightResponse, Validator,
};
use secretrs::proto::tendermint::v0_34::p2p::DefaultNodeInfo;
use secretrs::tendermint::block::{Block, Height, Id};
use tonic::{
    body::BoxBody,
    client::GrpcService,
    codegen::{Body, Bytes, StdError},
};

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

impl<T> TendermintQuerier<T>
where
    T: GrpcService<BoxBody> + Clone,
    T::Error: Into<StdError>,
    T::ResponseBody: Body<Data = Bytes> + Send + 'static,
    <T::ResponseBody as Body>::Error: Into<StdError> + Send,
{
    pub async fn get_node_info(&self) -> Result<GetNodeInfoResponse> {
        let request = GetNodeInfoRequest {};
        let response: ::tonic::Response<GetNodeInfoResponse> =
            self.inner.clone().get_node_info(request).await?;

        Ok(response.into_inner())

        // let default_node_info =
        //     response
        //         .into_inner()
        //         .default_node_info
        //         .ok_or(Error::MissingField {
        //             name: "default_node_info",
        //         })?;
        // Ok(default_node_info)
    }

    pub async fn get_syncing(&self) -> Result<bool> {
        let request = GetSyncingRequest {};
        let response: ::tonic::Response<GetSyncingResponse> =
            self.inner.clone().get_syncing(request).await?;

        let syncing = response.into_inner().syncing;
        Ok(syncing)
    }

    pub async fn get_latest_block(&self) -> Result<Block> {
        let request = GetLatestBlockRequest {};
        let response: ::tonic::Response<GetLatestBlockResponse> =
            self.inner.clone().get_latest_block(request).await?;

        let block = response
            .into_inner()
            .block
            .ok_or(Error::MissingField { name: "block" })?;
        Ok(Block::try_from(block)?)
    }

    pub async fn get_block_by_height(&self, height: impl Into<Height>) -> Result<Block> {
        let height = i64::from(height.into());

        let request = GetBlockByHeightRequest { height };
        let response: ::tonic::Response<GetBlockByHeightResponse> =
            self.inner.clone().get_block_by_height(request).await?;

        let block = response
            .into_inner()
            .block
            .ok_or(Error::MissingField { name: "block" })?;
        Ok(Block::try_from(block)?)
    }

    // TODO: deal with pagination
    pub async fn get_latest_validator_set(
        &self,
        pagination: Option<PageRequest>,
    ) -> Result<Vec<Validator>> {
        let request = GetLatestValidatorSetRequest { pagination };
        let response: ::tonic::Response<GetLatestValidatorSetResponse> =
            self.inner.clone().get_latest_validator_set(request).await?;

        // TODO: convert this type of Validator into a more advanced type (if there is one)
        let validators = response.into_inner().validators;
        Ok(validators)
    }

    // TODO: deal with pagination
    pub async fn get_validator_set_by_height(
        &self,
        height: impl Into<Height>,
        pagination: Option<PageRequest>,
    ) -> Result<Vec<Validator>> {
        let height = i64::from(height.into());

        let request = GetValidatorSetByHeightRequest { height, pagination };
        let response: ::tonic::Response<GetValidatorSetByHeightResponse> = self
            .inner
            .clone()
            .get_validator_set_by_height(request)
            .await?;

        // TODO: convert this type of Validator into a more advanced type (if there is one)
        let validators = response.into_inner().validators;
        Ok(validators)
    }

    pub async fn abci_query(&self, request: AbciQueryRequest) -> Result<AbciQueryResponse> {
        let response = self.inner.clone().abci_query(request).await?;
        Ok(response.into_inner())
    }
}
