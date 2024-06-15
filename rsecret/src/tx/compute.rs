use crate::query::auth::BaseAccount;
use crate::query::auth::QueryAccountRequest;
use crate::secret_network_client::CreateTxSenderOptions;
use crate::wallet::wallet_amino::AminoWallet;
use crate::wallet::Wallet;
use crate::wallet::WalletOptions;
use std::str::FromStr;
use std::sync::Arc;

use super::{Error, Result};
use crate::{query::auth::AuthQuerier, CreateClientOptions, TxOptions};
pub use secretrs::compute::{MsgExecuteContract, MsgInstantiateContract, MsgStoreCode};
use secretrs::{
    crypto::PublicKey,
    grpc_clients::{AuthQueryClient, TxServiceClient},
    proto::cosmos::{
        base::abci::v1beta1::TxResponse,
        tx::v1beta1::{BroadcastTxRequest, BroadcastTxResponse},
    },
    tx::{Body as TxBody, BodyBuilder, Fee, Msg, Raw, SignDoc, SignerInfo, Tx},
    Coin, EncryptionUtils,
};
use std::collections::HashMap;
use tonic::codegen::{Body, Bytes, StdError};

#[derive(Debug)]
pub struct ComputeServiceClient<T>
where
    T: tonic::client::GrpcService<tonic::body::BoxBody>,
    T::Error: Into<StdError>,
    T::ResponseBody: Body<Data = Bytes> + Send + 'static,
    <T::ResponseBody as Body>::Error: Into<StdError> + Send,
    T: Clone,
{
    inner: TxServiceClient<T>,
    auth: AuthQueryClient<T>,
    wallet: Arc<Wallet>,
    wallet_address: Arc<str>,
    encryption_utils: EncryptionUtils,
    code_hash_cache: HashMap<String, String>,
}

#[cfg(not(target_arch = "wasm32"))]
impl ComputeServiceClient<::tonic::transport::Channel> {
    pub async fn connect(options: CreateTxSenderOptions) -> Result<Self> {
        let channel = tonic::transport::Channel::from_static(options.url)
            .connect()
            .await?;
        Ok(Self::new(channel, options))
    }
    pub fn new(channel: ::tonic::transport::Channel, options: CreateTxSenderOptions) -> Self {
        let inner = TxServiceClient::new(channel.clone());
        let auth = AuthQueryClient::new(channel);

        let wallet = options.wallet;
        let wallet_address = options.wallet_address;
        let encryption_utils = options.encryption_utils;
        let code_hash_cache = HashMap::new();

        Self {
            inner,
            auth,
            wallet,
            wallet_address,
            encryption_utils,
            code_hash_cache,
        }
    }
}

// TODO: add auth querier
#[cfg(target_arch = "wasm32")]
impl ComputeServiceClient<::tonic_web_wasm_client::Client> {
    pub fn new(client: ::tonic_web_wasm_client::Client, options: CreateTxSenderOptions) -> Self {
        let inner = TxServiceClient::new(channel.clone());
        let auth = AuthQueryClient::new(channel);

        let wallet = options.wallet;
        let wallet_address = options.wallet_address;
        let encryption_utils = options.encryption_utils;
        let code_hash_cache = HashMap::new();

        Self {
            inner,
            auth,
            wallet,
            wallet_address,
            encryption_utils,
            code_hash_cache,
        }
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
        let tx_request = self.prepare_tx(msg, tx_options).await?;
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

    async fn prepare_tx<M: secretrs::tx::Msg>(
        &self,
        msg: M,
        tx_options: TxOptions,
    ) -> Result<BroadcastTxRequest> {
        let request = BroadcastTxRequest {
            tx_bytes: vec![],
            mode: tx_options.broadcast_mode.into(),
        };

        let accounts = self.wallet.get_accounts().await;
        let account = accounts.first().expect("no accounts");
        let address = account.address.clone();
        let public_key =
            secretrs::tendermint::PublicKey::from_raw_secp256k1(&account.pubkey.clone())
                .expect("invalid raw secp256k1 key bytes")
                .into();

        let request = QueryAccountRequest { address };
        let response = self.auth.clone().account(request).await?;

        let (metadata, response, _) = response.into_parts();

        let http_headers = metadata.into_headers();
        let block_height_header = http_headers
            .get("x-cosmos-block-height")
            .expect("x-cosmos-block-height missing");

        let block_height_str = block_height_header
            .to_str()
            .expect("Failed to convert header value to string");

        let block_height =
            u32::from_str(block_height_str).expect("Failed to parse block height into u32");

        let account = response
            .account
            .and_then(|any| any.to_msg::<BaseAccount>().ok())
            .ok_or_else(|| Error::custom("No account found"))?;

        // TODO: how to get chain ID here?
        let chain_id = "secretdev-1".parse()?;
        let account_number = account.account_number;
        let sequence = account.sequence;
        let memo = "";
        let timeout_height = block_height + 10;

        let gas = tx_options.gas_limit;
        let gas_price = tx_options.gas_price_in_fee_denom;
        let gas_fee_amount = gas as u128 * (gas_price * 1000000.0) as u128 / 1000000u128;
        let gas_fee = Coin {
            amount: gas_fee_amount,
            denom: "uscrt".parse()?,
        };

        let tx_body = TxBody::new(vec![msg.to_any()?], memo, timeout_height);
        let signer_info = SignerInfo::single_direct(Some(public_key), sequence);
        let auth_info = signer_info.auth_info(Fee::from_amount_and_gas(gas_fee, gas));
        let sign_doc = SignDoc::new(&tx_body, &auth_info, &chain_id, account_number)?;

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
