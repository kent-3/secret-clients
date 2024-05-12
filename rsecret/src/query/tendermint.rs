// use anyhow::{Error, Result};
use crate::{Error, Result};
use secretrs::grpc_clients::TendermintServiceClient;
use secretrs::proto::cosmos::base::query::v1beta1::PageRequest;
use secretrs::proto::cosmos::base::tendermint::v1beta1::{
    AbciQueryRequest, AbciQueryResponse, GetBlockByHeightRequest, GetBlockByHeightResponse,
    GetLatestBlockRequest, GetLatestBlockResponse, GetLatestValidatorSetRequest,
    GetLatestValidatorSetResponse, GetNodeInfoRequest, GetNodeInfoResponse, GetSyncingRequest,
    GetSyncingResponse, GetValidatorSetByHeightRequest, GetValidatorSetByHeightResponse, Validator,
};
use secretrs::tendermint::block::{Block, Height, Id};
use tonic::codegen::{Body, Bytes, StdError};
use tracing::{debug, debug_span, trace};

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
    pub async fn get_node_info(&self) -> Result<GetNodeInfoResponse> {
        let request = GetNodeInfoRequest {};
        self.inner
            .clone()
            .get_node_info(request)
            .await
            .map_err(Into::into)
            .map(::tonic::Response::into_inner)
    }
    pub async fn get_syncing(&self) -> Result<GetSyncingResponse> {
        let request = GetSyncingRequest {};
        self.inner
            .clone()
            .get_syncing(request)
            .await
            .map_err(Into::into)
            .map(::tonic::Response::into_inner)
    }
    pub async fn get_latest_block(&self) -> Result<Block> {
        let request = GetLatestBlockRequest {};
        let response: ::tonic::Response<GetLatestBlockResponse> =
            self.inner.clone().get_latest_block(request).await?;
        let (metadata, response, _) = response.into_parts();
        {
            let http_headers = metadata.into_headers();
            let block_height = http_headers.get("x-cosmos-block-height");
            debug!("x-cosmos-block-height: {:?}", block_height);
        }
        let block = response.block.ok_or("missing field: 'block'")?;
        Ok(Block::try_from(block)?)
    }
    pub async fn get_block_by_height(&self, height: impl Into<Height>) -> Result<Block> {
        let height = i64::from(height.into());
        let request = GetBlockByHeightRequest { height };
        let response: ::tonic::Response<GetBlockByHeightResponse> =
            self.inner.clone().get_block_by_height(request).await?;
        let (metadata, response, _) = response.into_parts();
        {
            let http_headers = metadata.into_headers();
            let block_height = http_headers.get("x-cosmos-block-height");
            debug!("x-cosmos-block-height: {:?}", block_height);
        }
        let block = response.block.ok_or("missing field: 'block'")?;
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
        let (metadata, response, _) = response.into_parts();
        {
            let http_headers = metadata.into_headers();
            let block_height = http_headers.get("x-cosmos-block-height");
            debug!("x-cosmos-block-height: {:?}", block_height);
        }
        let validators = response.validators;
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
        let (metadata, response, _) = response.into_parts();
        {
            let http_headers = metadata.into_headers();
            let block_height = http_headers.get("x-cosmos-block-height");
            debug!("x-cosmos-block-height: {:?}", block_height);
        }
        let validators = response.validators;
        Ok(validators)
    }
    // TODO: what is this used for?
    pub async fn abci_query(&self, request: AbciQueryRequest) -> Result<AbciQueryResponse> {
        self.inner
            .clone()
            .abci_query(request)
            .await
            .map_err(Into::into)
            .map(::tonic::Response::into_inner)
    }
}

// mod transforms {
//     use secretrs::proto;
//     use secretrs::tendermint::block::{Block, Id};
//     use secretrs::{Error, ErrorReport, Result};
//
//     #[derive(Debug, Clone)]
//     pub struct GetLatestBlockResponse {
//         pub block_id: Id,
//         pub block: Block,
//     }
//
//     impl TryFrom<proto::cosmos::base::tendermint::v1beta1::GetLatestBlockResponse>
//         for GetLatestBlockResponse
//     {
//         type Error = ErrorReport;
//
//         fn try_from(
//             proto: proto::cosmos::base::tendermint::v1beta1::GetLatestBlockResponse,
//         ) -> Result<GetLatestBlockResponse> {
//             Ok(GetLatestBlockResponse {
//                 block_id: proto
//                     .block_id
//                     .ok_or(Error::MissingField { name: "block_id" })?
//                     .try_into()?,
//                 block: proto
//                     .block
//                     .ok_or(Error::MissingField { name: "block" })?
//                     .try_into()?,
//             })
//         }
//     }
//
//     impl From<GetLatestBlockResponse>
//         for proto::cosmos::base::tendermint::v1beta1::GetLatestBlockResponse
//     {
//         fn from(value: GetLatestBlockResponse) -> Self {
//             Self {
//                 block_id: Some(value.block_id.into()),
//                 block: Some(value.block.into()),
//                 sdk_block: None,
//             }
//         }
//     }
// }
