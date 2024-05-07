use super::{Error, Result};
use secretrs::clients::TxServiceClient;
use secretrs::proto::cosmos::tx::v1beta1::{
    BroadcastTxRequest, BroadcastTxResponse, GetBlockWithTxsRequest, GetBlockWithTxsResponse,
    GetTxRequest, GetTxResponse, GetTxsEventRequest, GetTxsEventResponse, SimulateRequest,
    SimulateResponse,
};
use tonic::codegen::{Body, Bytes, StdError};

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
    T: tonic::client::GrpcService<tonic::body::BoxBody>,
    T::Error: Into<StdError>,
    T::ResponseBody: Body<Data = Bytes> + Send + 'static,
    <T::ResponseBody as Body>::Error: Into<StdError> + Send,
    T: Clone,
{
    pub async fn simulate(&mut self, request: SimulateRequest) -> Result<SimulateResponse> {
        self.inner
            .simulate(request)
            .await
            .map_err(Into::into)
            .map(::tonic::Response::into_inner)

        // A SimulateResponse contains:
        // * Option<GasInfo>
        // * Option<Result>
    }

    /// `hash` is the tx hash to query, encoded as a hex string.
    pub async fn get_tx(&mut self, hash: impl Into<String>) -> Result<GetTxResponse> {
        let hash = hash.into();
        let request = GetTxRequest { hash };
        self.inner
            .get_tx(request)
            .await
            .map_err(Into::into)
            .map(::tonic::Response::into_inner)

        // A GetTxResponse contains:
        // * Option<Tx>
        // * Option<TxResponse>
    }
    pub async fn get_txs_event(
        &mut self,
        request: GetTxsEventRequest,
    ) -> Result<GetTxsEventResponse> {
        self.inner
            .get_txs_event(request)
            .await
            .map_err(Into::into)
            .map(::tonic::Response::into_inner)
    }
    pub async fn get_block_with_txs(
        &mut self,
        request: GetBlockWithTxsRequest,
    ) -> Result<GetBlockWithTxsResponse> {
        self.inner
            .get_block_with_txs(request)
            .await
            .map_err(Into::into)
            .map(::tonic::Response::into_inner)
    }
}
