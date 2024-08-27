use crate::query::auth::BaseAccount;
use crate::query::auth::QueryAccountRequest;
use crate::secret_network_client::CreateTxSenderOptions;
use crate::secret_network_client::TxResponse;
use crate::wallet::AminoSigner;
use crate::wallet::DirectSigner;
use crate::wallet::Wallet;
use crate::wallet::WalletOptions;
use base64::prelude::{Engine as _, BASE64_STANDARD};
use prost::Message;
use secretrs::abci::MsgData;
use secretrs::proto::secret::compute::v1beta1::{
    MsgExecuteContractResponse, MsgInstantiateContractResponse, MsgMigrateContractResponse,
};
use secretrs::Any;

use secretrs::utils::encryption::SecretMsg;
use serde::Serialize;
use std::str::FromStr;
use std::sync::Arc;
use tracing::{debug, info};

use super::{Error, Result};
use crate::{query::auth::AuthQuerier, CreateClientOptions, TxOptions};
use secretrs::compute::{
    MsgExecuteContract, MsgInstantiateContract, MsgMigrateContract, MsgStoreCode,
};
use secretrs::{
    crypto::PublicKey,
    grpc_clients::{AuthQueryClient, TxServiceClient},
    proto::cosmos::{
        base::abci::v1beta1::TxResponse as TxResponseProto,
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

// use crate::macros::impl_as_ref_for_service_client;
// impl_as_ref_for_service_client!(ComputeServiceClient<T>);

type ComputeMsgToNonce = HashMap<u16, [u8; 32]>;

use crate::secret_network_client::Enigma;
impl<T> Enigma for ComputeServiceClient<T>
where
    T: tonic::client::GrpcService<tonic::body::BoxBody>,
    T::Error: Into<StdError>,
    T::ResponseBody: Body<Data = Bytes> + Send + 'static,
    <T::ResponseBody as Body>::Error: Into<StdError> + Send,
    T: Clone,
{
    fn encrypt<M: Serialize>(&self, contract_code_hash: &str, msg: &M) -> Result<SecretMsg> {
        self.encryption_utils
            .encrypt(contract_code_hash, msg)
            .map_err(Into::into)
    }

    fn decrypt(&self, nonce: &[u8; 32], ciphertext: &[u8]) -> Result<Vec<u8>> {
        self.encryption_utils
            .decrypt(nonce, ciphertext)
            .map_err(Into::into)
    }

    fn decrypt_tx_response<'a>(
        &'a self,
        tx_response: &'a mut TxResponse,
    ) -> Result<&'a mut TxResponse> {
        let mut nonces = ComputeMsgToNonce::new();

        for (msg_index, any) in tx_response.tx.body.messages.iter_mut().enumerate() {
            // Check if the message needs decryption
            match any.type_url.as_str() {
                "/secret.compute.v1beta1.MsgInstantiateContract" => {
                    debug!("found an encrypted message!");
                    // let mut msg = any.to_msg::<MsgInstantiateContract>()?;
                    let mut msg = MsgInstantiateContract::from_any(any)?;
                    let mut nonce = [0u8; 32];
                    nonce.copy_from_slice(&msg.init_msg[0..32]);
                    let ciphertext = &msg.init_msg[64..];

                    if let Ok(plaintext) = self.decrypt(&nonce, ciphertext) {
                        // we only insert the nonce in the hashmap if we were able to use it!
                        nonces.insert(msg_index as u16, nonce);
                        msg.init_msg = serde_json::from_slice(&plaintext[64..])?;

                        *any = msg.into_any()?
                    }
                    debug!("unable to decrypt... oh well!");
                }
                "/secret.compute.v1beta1.MsgExecuteContract" => {
                    debug!("found an encrypted message!");
                    let mut msg = MsgExecuteContract::from_any(any)?;
                    let mut nonce = [0u8; 32];
                    nonce.copy_from_slice(&msg.msg[0..32]);
                    let ciphertext = &msg.msg[64..];

                    if let Ok(plaintext) = self.decrypt(&nonce, ciphertext) {
                        nonces.insert(msg_index as u16, nonce);
                        msg.msg = serde_json::from_slice(&plaintext[64..])?;

                        *any = msg.into_any()?
                    }
                    debug!("unable to decrypt... oh well!");
                }
                "/secret.compute.v1beta1.MsgMigrateContract" => {
                    debug!("found an encrypted message!");
                    let mut msg = MsgMigrateContract::from_any(any)?;
                    let mut nonce = [0u8; 32];
                    nonce.copy_from_slice(&msg.msg[0..32]);
                    let ciphertext = &msg.msg[64..];

                    if let Ok(plaintext) = self.decrypt(&nonce, ciphertext) {
                        nonces.insert(msg_index as u16, nonce);
                        msg.msg = serde_json::from_slice(&plaintext[64..])?;

                        *any = msg.into_any()?
                    }
                    debug!("unable to decrypt... oh well!");
                }
                // If the message is not of type MsgInstantiateContract, MsgExecuteContract, or
                // MsgMigrateContract, leave it unchanged. It doesn't require any decryption.
                _ => {
                    debug!("no encrypted messages here!");
                }
            };
        }

        // NOTE: This part is confusing!
        // `TxMsgData` has two fields: `data: Vec<MsgData>` and `msg_responses: Vec<Any>`.
        //     * `data` was deprecated in v0.46, but secret is currently v0.45
        //     * `msg_responnses` is currently empty
        // `MsgData` is like a pseudo-Any. It has two fields: `msg_type: String` and `data: Vec<u8>`.
        //     * `msg_type` is the type of message that `data` is the response for

        #[allow(deprecated)]
        for (msg_index, msg_data) in tx_response.data.iter_mut().enumerate() {
            // Check if the message needs decryption (has an associated nonce from earlier)
            if let Some(nonce) = nonces.get(&(msg_index as u16)) {
                match msg_data.msg_type.as_str() {
                    // if the message was a MsgInstantiateContract, then the data is in the form of
                    // MsgInstantiateContractResponse. same goes for Execute and Migrate.
                    "/secret.compute.v1beta1.MsgInstantiateContract" => {
                        debug!("found an encrypted message!");
                        let mut decoded =
                            <MsgInstantiateContractResponse as Message>::decode(&*msg_data.data)?;

                        if let Ok(bytes) = self.decrypt(&nonce, &decoded.data) {
                            let msg_type =
                                "/secret.compute.v1beta1.MsgInstantiateContract".to_string();
                            let data = BASE64_STANDARD.decode(String::from_utf8(bytes)?)?;

                            *msg_data = MsgData { msg_type, data }
                        }
                        debug!("unable to decrypt... oh well!");
                    }
                    "/secret.compute.v1beta1.MsgExecuteContract" => {
                        debug!("found an encrypted message!");
                        let mut decoded =
                            <MsgExecuteContractResponse as Message>::decode(&*msg_data.data)?;

                        if let Ok(bytes) = self.decrypt(&nonce, &decoded.data) {
                            let msg_type = "/secret.compute.v1beta1.MsgExecuteContract".to_string();
                            let data = BASE64_STANDARD.decode(String::from_utf8(bytes)?)?;

                            *msg_data = MsgData { msg_type, data }
                        }
                        debug!("unable to decrypt... oh well!");
                    }
                    "/secret.compute.v1beta1.MsgMigrateContract" => {
                        debug!("found an encrypted message!");
                        let mut decoded =
                            <MsgMigrateContractResponse as Message>::decode(&*msg_data.data)?;
                        if let Ok(bytes) = self.decrypt(&nonce, &decoded.data) {
                            let msg_type = "/secret.compute.v1beta1.MsgMigrateContract".to_string();
                            let data = BASE64_STANDARD.decode(String::from_utf8(bytes)?)?;

                            *msg_data = MsgData { msg_type, data }
                        }
                        debug!("unable to decrypt... oh well!");
                    }
                    // If the message is not of type MsgInstantiateContract MsgExecuteContract,
                    // or MsgMigrateContract, leave it unchanged. It doesn't require any decryption.
                    _ => {
                        debug!("no encrypted messages here!");
                    }
                };
            }
        }

        // TODO: decrypt the logs
        // TODO: decrypt the events

        Ok(tx_response)

        // Ok(TxResponse {
        //     height: tx_response.height as u64,
        //     txhash: tx_response.txhash.to_uppercase(),
        //     code: tx_response.code,
        //     codespace: tx_response.codespace,
        //     data,
        //     raw_log: tx_response.raw_log,
        //     logs,
        //     ibc_responses,
        //     info: tx_response.info,
        //     gas_wanted: tx_response.gas_wanted as u64,
        //     gas_used: tx_response.gas_used as u64,
        //     tx,
        //     timestamp: tx_response.timestamp,
        //     events,
        // })
    }
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
        let inner = TxServiceClient::new(client.clone());
        let auth = AuthQueryClient::new(client);

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
    // TODO: I think all the input and output message types should be the proto versions?
    pub async fn store_code(
        &self,
        msg: MsgStoreCode,
        tx_options: TxOptions,
    ) -> Result<TxResponseProto> {
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
    ) -> Result<TxResponseProto> {
        todo!()
    }

    pub async fn execute_contract(
        &self,
        msg: MsgExecuteContract,
        tx_options: TxOptions,
    ) -> Result<TxResponseProto> {
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

        let accounts = self.wallet.get_accounts().await?;
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
