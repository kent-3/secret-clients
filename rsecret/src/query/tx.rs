use super::{Error, Result};
pub use secretrs::{
    grpc_clients::TxServiceClient,
    proto::cosmos::tx::v1beta1::{
        BroadcastTxRequest, BroadcastTxResponse, GetBlockWithTxsRequest, GetBlockWithTxsResponse,
        GetTxRequest, GetTxResponse, GetTxsEventRequest, GetTxsEventResponse, SimulateRequest,
        SimulateResponse,
    },
};
use tonic::{
    body::BoxBody,
    client::GrpcService,
    codegen::{Body, Bytes, StdError},
};

#[derive(Debug, Clone)]
pub struct TxQuerier<T> {
    inner: TxServiceClient<T>,
}

#[cfg(not(target_arch = "wasm32"))]
impl TxQuerier<::tonic::transport::Channel> {
    pub fn new(channel: ::tonic::transport::Channel) -> Self {
        let inner = TxServiceClient::new(channel);
        Self { inner }
    }
}

#[cfg(target_arch = "wasm32")]
impl TxQuerier<::tonic_web_wasm_client::Client> {
    pub fn new(client: ::tonic_web_wasm_client::Client) -> Self {
        let inner = TxServiceClient::new(client);
        Self { inner }
    }
}

// TODO - add abstractions to make calling these methods easier? like I did with `get_tx`

impl<T> TxQuerier<T>
where
    T: GrpcService<BoxBody> + Clone,
    T::Error: Into<StdError>,
    T::ResponseBody: Body<Data = Bytes> + Send + 'static,
    <T::ResponseBody as Body>::Error: Into<StdError> + Send,
{
    pub async fn simulate(&self, request: SimulateRequest) -> Result<SimulateResponse> {
        self.inner
            .clone()
            .simulate(request)
            .await
            .map_err(Into::into)
            .map(::tonic::Response::into_inner)

        // A SimulateResponse contains:
        // * Option<GasInfo>
        // * Option<Result>
    }

    /// `hash` is the tx hash to query, encoded as a hex string.
    pub async fn get_tx(&self, hash: impl Into<String>) -> Result<GetTxResponse> {
        let hash = hash.into();
        let request = GetTxRequest { hash };
        self.inner
            .clone()
            .get_tx(request)
            .await
            .map_err(Into::into)
            .map(::tonic::Response::into_inner)

        // TODO: Decide on response type...
        // A GetTxResponse contains:
        // * Option<Tx>
        // * Option<TxResponse>
        // The client seems to want the TxResponse, which seems to contain the Tx bytes anyway...
    }
    pub async fn get_txs_event(&self, request: GetTxsEventRequest) -> Result<GetTxsEventResponse> {
        self.inner
            .clone()
            .get_txs_event(request)
            .await
            .map_err(Into::into)
            .map(::tonic::Response::into_inner)
    }
    pub async fn get_block_with_txs(
        &self,
        request: GetBlockWithTxsRequest,
    ) -> Result<GetBlockWithTxsResponse> {
        self.inner
            .clone()
            .get_block_with_txs(request)
            .await
            .map_err(Into::into)
            .map(::tonic::Response::into_inner)
    }
}
