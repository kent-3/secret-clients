use super::{Error, Result};
use crate::TxOptions;
pub use secretrs::proto::cosmos::gov::v1beta1::{
    MsgDeposit, MsgSubmitProposal, MsgVote, MsgVoteWeighted,
};
use secretrs::{
    grpc_clients::TxServiceClient,
    proto::cosmos::{
        base::abci::v1beta1::TxResponse,
        tx::v1beta1::{BroadcastTxRequest, BroadcastTxResponse},
    },
    tx::{BodyBuilder, Msg, Raw, SignDoc, Tx},
};
use tonic::codegen::{Body, Bytes, StdError};

#[derive(Debug, Clone)]
pub struct GovServiceClient<T>
where
    T: tonic::client::GrpcService<tonic::body::BoxBody>,
    T::Error: Into<StdError>,
    T::ResponseBody: Body<Data = Bytes> + Send + 'static,
    <T::ResponseBody as Body>::Error: Into<StdError> + Send,
    T: Clone,
{
    inner: TxServiceClient<T>,
}

#[cfg(not(target_arch = "wasm32"))]
impl GovServiceClient<::tonic::transport::Channel> {
    pub fn new(channel: ::tonic::transport::Channel) -> Self {
        let inner = TxServiceClient::new(channel);
        Self { inner }
    }
}

#[cfg(target_arch = "wasm32")]
impl GovServiceClient<::tonic_web_wasm_client::Client> {
    pub fn new(client: ::tonic_web_wasm_client::Client) -> Self {
        let inner = TxServiceClient::new(client);
        Self { inner }
    }
}

impl<T> GovServiceClient<T>
where
    T: tonic::client::GrpcService<tonic::body::BoxBody>,
    T::Error: Into<StdError>,
    T::ResponseBody: Body<Data = Bytes> + Send + 'static,
    <T::ResponseBody as Body>::Error: Into<StdError> + Send,
    T: Clone,
{
    pub async fn vote(&self, msg: MsgVote, tx_options: TxOptions) -> Result<TxResponse> {
        todo!()
    }

    pub async fn vote_weighted(
        &self,
        msg: MsgVoteWeighted,
        tx_options: TxOptions,
    ) -> Result<TxResponse> {
        todo!()
    }

    pub async fn deposit(&self, msg: MsgDeposit, tx_options: TxOptions) -> Result<TxResponse> {
        todo!()
    }

    pub async fn submit_proposal(
        &self,
        msg: MsgSubmitProposal,
        tx_options: TxOptions,
    ) -> Result<TxResponse> {
        todo!()
    }

    fn prepare_tx<M: secretrs::proto::traits::Message>(
        &self,
        msg: M,
        tx_options: TxOptions,
    ) -> BroadcastTxRequest {
        todo!()
    }

    async fn sign(&self, sign_doc: SignDoc) -> Result<Raw> {
        todo!()
    }

    async fn perform(
        &self,
        request: BroadcastTxRequest,
    ) -> ::tonic::Result<::tonic::Response<BroadcastTxResponse>, ::tonic::Status> {
        self.inner.clone().broadcast_tx(request).await
    }
}
