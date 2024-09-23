use super::{Error, Result};
use crate::TxOptions;
pub use secretrs::bank::{MsgMultiSend, MsgSend};
use secretrs::{
    grpc_clients::TxServiceClient,
    proto::cosmos::{
        base::abci::v1beta1::TxResponse,
        tx::v1beta1::{BroadcastTxRequest, BroadcastTxResponse},
    },
    tendermint::chain,
    tx::{Body, Msg, Raw, SignDoc},
};

#[derive(Debug, Clone)]
pub struct BankServiceClient<T>
where
    T: tonic::client::GrpcService<tonic::body::BoxBody>,
    T::Error: Into<tonic::codegen::StdError>,
    T::ResponseBody: tonic::codegen::Body<Data = tonic::codegen::Bytes> + Send + 'static,
    <T::ResponseBody as tonic::codegen::Body>::Error: Into<tonic::codegen::StdError> + Send,
    T: Clone,
{
    inner: TxServiceClient<T>,
}

use crate::macros::impl_as_ref_for_service_client;
impl_as_ref_for_service_client!(BankServiceClient<T>);

#[cfg(not(target_arch = "wasm32"))]
impl BankServiceClient<::tonic::transport::Channel> {
    pub fn new(channel: ::tonic::transport::Channel) -> Self {
        let inner = TxServiceClient::new(channel);
        Self { inner }
    }
}

#[cfg(target_arch = "wasm32")]
impl BankServiceClient<::tonic_web_wasm_client::Client> {
    pub fn new(client: ::tonic_web_wasm_client::Client) -> Self {
        let inner = TxServiceClient::new(client);
        Self { inner }
    }
}

impl<T> BankServiceClient<T>
where
    T: tonic::client::GrpcService<tonic::body::BoxBody>,
    T::Error: Into<tonic::codegen::StdError>,
    T::ResponseBody: tonic::codegen::Body<Data = tonic::codegen::Bytes> + Send + 'static,
    <T::ResponseBody as tonic::codegen::Body>::Error: Into<tonic::codegen::StdError> + Send,
    T: Clone,
{
    pub async fn send(&self, msg: MsgSend, tx_options: TxOptions) -> Result<TxResponse> {
        let tx_body = self.prepare_tx(msg, tx_options)?;
        let tx_request = BroadcastTxRequest {
            tx_bytes: tx_body.into_bytes()?,
            mode: 1,
        };
        let tx_response = self
            .perform(tx_request)
            .await?
            .into_inner()
            .tx_response
            .ok_or("no response")?;

        Ok(tx_response)
    }

    pub async fn multi_send(&self, msg: MsgMultiSend, tx_options: TxOptions) -> Result<TxResponse> {
        todo!()
    }

    fn prepare_tx<M: Msg>(&self, msg: M, tx_options: TxOptions) -> Result<Body> {
        // TODO: find a way to get chain_id
        let chain_id: chain::Id = "secretdev-1".parse()?;

        // TODO: figure out how to use an AuthQuerier here to get account_number and sequence_number
        let account_number = 0;
        let account_sequence = 1;

        let gas = tx_options.gas_limit;
        // TODO: figure out what to set this timeout_height to
        let timeout_height = 99999999u32;
        let memo = tx_options.memo;

        let tx_body = Body::new(vec![msg.to_any()?], memo, timeout_height);

        Ok(tx_body)
    }

    async fn sign(&self, sign_doc: SignDoc) -> Result<Raw> {
        // let signer_info = SignerInfo::single_direct(Some(sender_public_key), account_sequence);
        // let auth_info = signer_info.auth_info(Fee::from_amount_and_gas(amount, gas));
        // let sign_doc = SignDoc::new(&tx_body, &auth_info, &chain_id, account_number)?;
        todo!()
    }

    async fn perform(
        &self,
        request: BroadcastTxRequest,
    ) -> ::tonic::Result<::tonic::Response<BroadcastTxResponse>, ::tonic::Status> {
        self.inner.clone().broadcast_tx(request).await
    }
}
