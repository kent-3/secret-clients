use super::{Error, Result};
use crate::{
    query::auth::{AuthQuerier, BaseAccount, QueryAccountRequest},
    secret_network_client::{
        CreateClientOptions, CreateTxSenderOptions, SignerData, TxOptions, TxResponse,
    },
    wallet::{
        wallet_amino::{AminoMsg, AminoSignResponse, StdFee, StdSignDoc, ToAmino},
        AccountData, DirectSignResponse, Signer, Wallet, WalletOptions,
    },
};
use async_trait::async_trait;
use base64::prelude::{Engine as _, BASE64_STANDARD};
use prost::Message;
use secretrs::{
    abci::MsgData,
    compute::{MsgExecuteContract, MsgInstantiateContract, MsgMigrateContract, MsgStoreCode},
    crypto::PublicKey,
    grpc_clients::{AuthQueryClient, TxServiceClient},
    proto::{
        cosmos::{
            base::abci::v1beta1::TxResponse as TxResponseProto,
            tx::v1beta1::{BroadcastTxRequest, BroadcastTxResponse, TxRaw},
        },
        secret::compute::v1beta1::{
            MsgExecuteContractResponse, MsgInstantiateContractResponse, MsgMigrateContractResponse,
        },
    },
    tx::{Body, BodyBuilder, Fee, Msg, Raw, SignDoc, SignMode, SignerInfo, Tx},
    utils::encryption::{EncryptionUtils, SecretMsg},
    AccountId, Any, Coin,
};
use serde::Serialize;
use std::{collections::HashMap, str::FromStr, sync::Arc};
use tracing::{debug, info, warn};

#[derive(Debug)]
pub struct ComputeServiceClient<T, S>
where
    T: tonic::client::GrpcService<tonic::body::BoxBody>,
    T::Error: Into<tonic::codegen::StdError>,
    T::ResponseBody: tonic::codegen::Body<Data = tonic::codegen::Bytes> + Send + 'static,
    <T::ResponseBody as tonic::codegen::Body>::Error: Into<tonic::codegen::StdError> + Send,
    T: Clone,
    S: Signer,
{
    inner: TxServiceClient<T>,
    auth: AuthQueryClient<T>,
    wallet: Arc<S>,
    wallet_address: Arc<str>,
    // TODO: add this here and everywhere
    chain_id: Arc<str>,
    encryption_utils: EncryptionUtils,
    code_hash_cache: HashMap<String, String>,
}

// use crate::macros::impl_as_ref_for_service_client;
// impl_as_ref_for_service_client!(ComputeServiceClient<T>);

type ComputeMsgToNonce = HashMap<u16, [u8; 32]>;

use crate::secret_network_client::Enigma;
impl<T, S> Enigma for ComputeServiceClient<T, S>
where
    T: tonic::client::GrpcService<tonic::body::BoxBody>,
    T::Error: Into<tonic::codegen::StdError>,
    T::ResponseBody: tonic::codegen::Body<Data = tonic::codegen::Bytes> + Send + 'static,
    <T::ResponseBody as tonic::codegen::Body>::Error: Into<tonic::codegen::StdError> + Send,
    T: Clone,
    S: Signer,
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

                        if let Ok(bytes) = self.decrypt(nonce, &decoded.data) {
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

                        if let Ok(bytes) = self.decrypt(nonce, &decoded.data) {
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
                        if let Ok(bytes) = self.decrypt(nonce, &decoded.data) {
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

        // use this if you want to return a new TxResponse instead of mutating the given one

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
impl<S> ComputeServiceClient<::tonic::transport::Channel, S>
where
    S: Signer,
{
    pub async fn connect(options: CreateTxSenderOptions<S>) -> Result<Self> {
        let channel = tonic::transport::Channel::from_static(options.url)
            .connect()
            .await?;
        Ok(Self::new(channel, options))
    }
    pub fn new(channel: ::tonic::transport::Channel, options: CreateTxSenderOptions<S>) -> Self {
        let inner = TxServiceClient::new(channel.clone());
        let auth = AuthQueryClient::new(channel);

        let wallet = options.wallet;
        let wallet_address = options.wallet_address;
        let chain_id = options.chain_id.into();
        let encryption_utils = options.encryption_utils;
        let code_hash_cache = HashMap::new();

        Self {
            inner,
            auth,
            wallet,
            wallet_address,
            chain_id,
            encryption_utils,
            code_hash_cache,
        }
    }
}

#[cfg(target_arch = "wasm32")]
impl<S: Signer> ComputeServiceClient<::tonic_web_wasm_client::Client, S> {
    pub fn new(client: ::tonic_web_wasm_client::Client, options: CreateTxSenderOptions<S>) -> Self {
        let inner = TxServiceClient::new(client.clone());
        let auth = AuthQueryClient::new(client);

        let wallet = options.wallet;
        let wallet_address = options.wallet_address;
        let chain_id = options.chain_id.into();
        let encryption_utils = options.encryption_utils;
        let code_hash_cache = HashMap::new();

        Self {
            inner,
            auth,
            wallet,
            wallet_address,
            chain_id,
            encryption_utils,
            code_hash_cache,
        }
    }
}

impl<T, S> ComputeServiceClient<T, S>
where
    T: tonic::client::GrpcService<tonic::body::BoxBody>,
    T::Error: Into<tonic::codegen::StdError>,
    T::ResponseBody: tonic::codegen::Body<Data = tonic::codegen::Bytes> + Send + 'static,
    <T::ResponseBody as tonic::codegen::Body>::Error: Into<tonic::codegen::StdError> + Send,
    T: Clone,
    S: Signer,
{
    // TODO: I think all the input and output message types should be the proto versions?
    pub async fn store_code(
        &self,
        msg: MsgStoreCode,
        tx_options: TxOptions,
    ) -> Result<TxResponseProto> {
        let tx_request = self.prepare_and_sign(vec![msg], tx_options).await?;
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
        code_hash: impl Into<String>,
        tx_options: TxOptions,
    ) -> Result<TxResponseProto> {
        let tx_request = self.prepare_and_sign(vec![msg], tx_options).await?;
        let tx_response = self
            .perform(tx_request)
            .await?
            .into_inner()
            .tx_response
            .ok_or("no response")?;

        Ok(tx_response)
    }

    pub async fn execute_contract(
        &self,
        msg: MsgExecuteContract,
        code_hash: impl Into<String>,
        tx_options: TxOptions,
    ) -> Result<TxResponseProto> {
        let tx_request = self.prepare_and_sign(vec![msg], tx_options).await?;
        let tx_response = self
            .perform(tx_request)
            .await?
            .into_inner()
            .tx_response
            .ok_or("no response")?;

        Ok(tx_response)
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

    async fn prepare_and_sign<M: secretrs::tx::Msg>(
        &self,
        messages: Vec<M>,
        tx_options: TxOptions,
    ) -> Result<BroadcastTxRequest> {
        let accounts = self.wallet.get_accounts().await.unwrap();
        let account = accounts.first().expect("no accounts");
        let address = account.address.clone();
        let public_key: PublicKey =
            secretrs::tendermint::PublicKey::from_raw_secp256k1(&account.pubkey.clone())
                .expect("invalid raw secp256k1 key bytes")
                .into();

        let request = QueryAccountRequest { address };
        let response = self.auth.clone().account(request).await?;

        let (metadata, response, _) = response.into_parts();

        let http_headers = metadata.into_headers();
        let block_height = http_headers
            .get("x-cosmos-block-height")
            .and_then(|header| header.to_str().ok())
            .and_then(|header_str| u32::from_str(header_str).ok())
            .expect("Failed to retrieve and parse block height");

        let account = response
            .account
            .and_then(|any| any.to_msg::<BaseAccount>().ok())
            .ok_or_else(|| Error::custom("No account found"))?;

        let chain_id = self.chain_id.to_string();
        let account_number = account.account_number;
        let sequence = account.sequence;
        let memo = tx_options.memo;
        let timeout_height = block_height + 10;

        let gas = tx_options.gas_limit;
        let gas_price = tx_options.gas_price_in_fee_denom;
        let gas_fee_amount = gas as u128 * (gas_price * 1000000.0) as u128 / 1000000u128;
        let gas_fee = Coin {
            amount: gas_fee_amount,
            denom: "uscrt".parse()?,
        };

        let fee = StdFee {
            gas: gas.to_string(),
            amount: vec![gas_fee],
            granter: None,
        };

        let explicit_signer_data = tx_options.explicit_signer_data;

        // let messages: Vec<Any> = messages
        //     .iter()
        //     .map(|msg| msg.to_any().map_err(Into::into))
        //     .collect()?;
        //
        // let tx_body = Body::new(messages, memo, timeout_height);
        // let signer_info = SignerInfo::single_direct(Some(public_key), sequence);
        // let auth_info = signer_info.auth_info(Fee::from_amount_and_gas(gas_fee, gas));
        // let sign_doc = SignDoc::new(&tx_body, &auth_info, &chain_id.parse()?, account_number)?;

        let tx_raw = self.sign(messages, fee, memo, explicit_signer_data).await?;
        let tx_bytes = tx_raw.encode_to_vec();

        Ok(BroadcastTxRequest { tx_bytes, mode: 1 })
    }

    /// Gets account number and sequence from the API, creates a sign doc,
    /// creates a single signature and assembles the signed transaction.
    ///
    /// The sign mode (SIGN_MODE_DIRECT or SIGN_MODE_LEGACY_AMINO_JSON) is determined by this client's signer.
    ///
    /// You can pass signer data (account number, sequence and chain ID) explicitly instead of querying them
    /// from the chain. This is needed when signing for a multisig account, but it also allows for offline signing.
    async fn sign(
        &self,
        messages: Vec<impl secretrs::tx::Msg>,
        fee: StdFee,
        memo: String,
        explicit_signer_data: Option<SignerData>,
    ) -> Result<TxRaw> {
        let signer = self.wallet.as_ref();
        let signer_address = self.wallet_address.as_ref();

        let account_from_signer: AccountData = signer
            .get_accounts()
            .await
            .map_err(crate::Error::custom)
            .and_then(|accounts| {
                accounts
                    .iter()
                    .find(|account| account.address == signer_address)
                    .cloned()
                    .ok_or_else(|| crate::Error::custom("Failed to retrieve account from signer"))
            })?;

        // TODO: match secret.js carefully. They do a lot more of the preparation inside of these
        // sign methods instead of in the "prepare_tx" method.

        // signerData = {
        //     accountNumber: Number(baseAccount.account_number),
        //     sequence: Number(baseAccount.sequence),
        //     chainId: this.chainId,
        //   };

        let request = QueryAccountRequest {
            address: signer_address.to_string(),
        };
        let response = self.auth.clone().account(request).await?;

        let (metadata, response, _) = response.into_parts();

        let http_headers = metadata.into_headers();
        let block_height = http_headers
            .get("x-cosmos-block-height")
            .and_then(|header| header.to_str().ok())
            .and_then(|header_str| u32::from_str(header_str).ok())
            .ok_or(Error::custom("Failed to retrieve and parse block height"))?;

        let account: BaseAccount = response
            .account
            .and_then(|any| any.to_msg::<BaseAccount>().ok())
            .ok_or(Error::custom("No account found"))?;

        let signer_data = SignerData {
            account_number: account.account_number,
            account_sequence: account.sequence,
            chain_id: self.chain_id.to_string(),
        };

        match signer.get_sign_mode().await.map_err(Error::custom)? {
            SignMode::LegacyAminoJson => {
                let signed_tx_raw: TxRaw = self
                    .sign_amino(account_from_signer, messages, fee, memo, signer_data)
                    .await?;

                Ok(signed_tx_raw.into())
            }
            SignMode::Direct => {
                let signed_tx_raw: TxRaw = self
                    .sign_direct(account_from_signer, messages, fee, memo, signer_data)
                    .await?;

                Ok(signed_tx_raw.into())
            }
            _ => Err(crate::Error::custom("Unsupported SignMode")),
        }
    }

    async fn sign_amino(
        &self,
        account: AccountData,
        // TODO: this will get annoying fast, if we have to put this bound everywhere.
        // It would be better to have a single unifying trait we could use...
        messages: Vec<impl secretrs::tx::Msg + ToAmino>,
        fee: StdFee,
        memo: String,
        signer_data: SignerData,
    ) -> Result<TxRaw> {
        // TODO: avoid having to make this check all over the place?
        let sign_mode = self
            .wallet
            .get_sign_mode()
            .await
            .map_err(crate::Error::custom)?;

        let SignMode::LegacyAminoJson = sign_mode else {
            return Err(crate::Error::custom(
                "Wrong signer type! Expected AminoSigner or AminoEip191Signer.",
            ));
        };

        // TODO:
        // 1) convert the messages to Amino messages + encrypt them
        // 2) create the SignDoc
        // 3) do self.wallet.sign_amino
        // 4) construct the tx_body, auth_info, etc using a mashup of the original messages, but
        //    the returned signed SignDoc for things like gas and memo changes
        // 5) turn all that into a TxRaw

        let amino_msgs: Vec<AminoMsg> = messages
            .iter()
            .map(|msg| msg.to_amino(self.encryption_utils.clone()))
            .collect();
        let serialized = serde_json::to_string(&amino_msgs).unwrap();
        debug!("Serialized AminoMsg: {}", serialized);

        let sign_doc = todo!();

        let response: AminoSignResponse = self
            .wallet
            .sign_amino(&account.address, sign_doc)
            .await
            .map_err(crate::Error::custom)?;

        let signed: StdSignDoc = response.signed;
        let signature = BASE64_STANDARD.decode(response.signature.signature)?;

        // let signed_tx_raw = TxRaw {
        //     body_bytes: signed.body_bytes,
        //     auth_info_bytes: signed.auth_info_bytes,
        //     signatures: vec![signature],
        // };

        // Ok(signed_tx_raw)

        todo!()
    }

    async fn sign_direct(
        &self,
        account: AccountData,
        messages: Vec<impl secretrs::tx::Msg>,
        fee: StdFee,
        memo: String,
        signer_data: SignerData,
    ) -> Result<TxRaw> {
        // TODO: avoid having to make this check all over the place?
        let sign_mode = self
            .wallet
            .get_sign_mode()
            .await
            .map_err(crate::Error::custom)?;

        let SignMode::Direct = sign_mode else {
            return Err(crate::Error::custom(
                "Wrong signer type! Expected DirectSigner.",
            ));
        };

        // let messages: Vec<Any> = messages
        //     .iter()
        //     .map(|msg| msg.to_any().map_err(Into::into))
        //     .collect()?;
        //
        // let tx_body = Body::new(messages, memo, timeout_height);
        // let signer_info = SignerInfo::single_direct(Some(public_key), sequence);
        // let auth_info = signer_info.auth_info(Fee::from_amount_and_gas(gas_fee, gas));
        // let sign_doc = SignDoc::new(&tx_body, &auth_info, &chain_id.parse()?, account_number)?;

        // TODO: create the SignDoc
        let sign_doc = todo!();

        let response: DirectSignResponse = self
            .wallet
            .sign_direct(&account.address, sign_doc)
            .await
            .map_err(crate::Error::custom)?;

        let signed = response.signed;
        let signature = BASE64_STANDARD.decode(response.signature.signature)?;

        let signed_tx_raw = TxRaw {
            body_bytes: signed.body_bytes,
            auth_info_bytes: signed.auth_info_bytes,
            signatures: vec![signature],
        };

        Ok(signed_tx_raw)
    }

    // TODO: I need a way to distinguish which message types need to be encrypted. Although, I
    // could just keep the 'compute' methods different from all the others... instead of giving
    // EncryptionUtils to every toProto/toAmino method and ignoring it for every other module
    // message type.

    // TODO: I might want to introduce a new trait for "messages that get encrypted", with methods
    // to_proto and to_amino, and each of those methods involves encrypting the inner message.

    // TODO: this function queries for contract code hashes if they are missing, but I'd need to
    // create new structs to represent the equivalents in secret.js.
    // Actually, I might ignore this and just have separate functions for those 3 message types
    // that need it...
    async fn populate_code_hash<M: secretrs::tx::Msg>(&self, msg: M) {
        todo!()
    }

    async fn perform(
        &self,
        request: BroadcastTxRequest,
    ) -> ::tonic::Result<::tonic::Response<BroadcastTxResponse>, ::tonic::Status> {
        self.inner.clone().broadcast_tx(request).await
    }
}
