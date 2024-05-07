#![allow(unused)]

use super::{Error, Result};
use crate::{CreateClientOptions, TxOptions};
use secretrs::{
    clients::TxServiceClient,
    compute::{MsgExecuteContract, MsgInstantiateContract, MsgStoreCode},
    proto::cosmos::{
        base::abci::v1beta1::TxResponse,
        tx::v1beta1::{BroadcastTxRequest, BroadcastTxResponse},
    },
    tx::{BodyBuilder, Msg, Raw, SignDoc, Tx},
    EncryptionUtils,
};
use std::collections::HashMap;
use std::sync::Arc;
use tonic::codegen::{Body, Bytes, StdError};

#[derive(Debug, Clone)]
pub struct ComputeServiceClient<T>
where
    T: tonic::client::GrpcService<tonic::body::BoxBody>,
    T::Error: Into<StdError>,
    T::ResponseBody: Body<Data = Bytes> + Send + 'static,
    <T::ResponseBody as Body>::Error: Into<StdError> + Send,
    T: Clone,
{
    inner: TxServiceClient<T>,
    encryption_utils: EncryptionUtils,
    code_hash_cache: HashMap<&'static str, String>,
}

#[cfg(not(target_arch = "wasm32"))]
impl ComputeServiceClient<::tonic::transport::Channel> {
    pub async fn connect(options: &CreateClientOptions) -> Result<Self> {
        let channel = tonic::transport::Channel::from_static(options.url)
            .connect()
            .await?;
        Ok(Self::new(channel, options))
    }
    pub fn new(channel: ::tonic::transport::Channel, options: &CreateClientOptions) -> Self {
        let inner = TxServiceClient::new(channel);
        let encryption_utils = EncryptionUtils::new(options.encryption_seed, options.chain_id)
            .expect("failed to create EncryptionUtils");
        let code_hash_cache = HashMap::new();
        Self {
            inner,
            encryption_utils,
            code_hash_cache,
        }
    }
}

#[cfg(target_arch = "wasm32")]
impl ComputeServiceClient<::tonic_web_wasm_client::Client> {
    pub fn new(client: ::tonic_web_wasm_client::Client) -> Self {
        let inner = TxServiceClient::new(client);
        Self { inner }
    }
}

impl<T> ComputeServiceClient<T>
where
    T: tonic::client::GrpcService<tonic::body::BoxBody>,
    T::Error: Into<StdError>,
    T::ResponseBody: Body<Data = Bytes> + Send + 'static,
    <T::ResponseBody as Body>::Error: Into<StdError> + Send,
    T: Clone,
{
    pub async fn store_code(&self, msg: MsgStoreCode, tx_options: TxOptions) -> Result<TxResponse> {
        let tx_request = self.prepare_tx(msg, tx_options);
        let tx_response = self
            .perform(tx_request)
            .await?
            .into_inner()
            .tx_response
            .ok_or("no response")?;

        Ok(tx_response)
    }

    pub async fn instantiate_contract(
        &self,
        msg: MsgInstantiateContract,
        tx_options: TxOptions,
    ) -> Result<TxResponse> {
        todo!()
    }

    pub async fn execute_contract(
        &self,
        msg: MsgExecuteContract,
        tx_options: TxOptions,
    ) -> Result<TxResponse> {
        todo!()
    }

    pub async fn migrate_contract() {
        todo!()
    }
    pub async fn update_admin() {
        todo!()
    }
    pub async fn clear_admin() {
        todo!()
    }

    fn prepare_tx<M: cosmrs::tx::Msg>(&self, msg: M, tx_options: TxOptions) -> BroadcastTxRequest {
        let request = BroadcastTxRequest {
            tx_bytes: vec![],
            mode: tx_options.broadcast_mode.into(),
        };

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
