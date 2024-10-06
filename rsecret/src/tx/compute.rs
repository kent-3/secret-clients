use super::{Error, Result};
use crate::{
    query::auth::{AuthQuerier, BaseAccount, QueryAccountRequest},
    secret_network_client::{
        CreateClientOptions, CreateTxSenderOptions, Enigma2, IbcTxOptions, SignerData, TxDecoder,
        TxOptions, TxResponse,
    },
    traits::{is_plaintext, ToAmino},
    wallet::{
        wallet_amino::{AminoMsg, AminoSignResponse, StdFee, StdSignDoc, StdSignature},
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
            tx::v1beta1::{
                BroadcastMode, BroadcastTxRequest, BroadcastTxResponse, Tx as TxPb, TxRaw,
            },
        },
        secret::compute::v1beta1::{
            MsgExecuteContractResponse, MsgInstantiateContractResponse, MsgMigrateContractResponse,
        },
    },
    tx::{
        Body as TxBody, BodyBuilder, Fee, MessageExt, ModeInfo, Msg, Raw, SignDoc, SignMode,
        SignerInfo, Tx,
    },
    utils::encryption::{EncryptionUtils, Enigma, SecretMsg},
    AccountId, Any, Coin,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};
use std::{collections::HashMap, str::FromStr, sync::Arc};
use tonic::{
    body::BoxBody,
    client::GrpcService,
    codegen::{Body, Bytes, StdError},
};
use tracing::{debug, info, warn};

#[derive(Debug)]
pub struct ComputeServiceClient<T, U, V>
where
    T: GrpcService<BoxBody> + Clone + Sync,
    T::Error: Into<StdError>,
    T::ResponseBody: Body<Data = Bytes> + Send + 'static,
    <T::ResponseBody as Body>::Error: Into<StdError> + Send,
    U: Enigma + Sync,
    V: Signer + Sync,
{
    inner: TxServiceClient<T>,
    auth: AuthQueryClient<T>,
    chain_id: Arc<str>,
    encryption_utils: Arc<U>,
    wallet: Arc<V>,
    wallet_address: Arc<str>,
    code_hash_cache: HashMap<String, String>,
}

// use crate::macros::impl_as_ref_for_service_client;
// impl_as_ref_for_service_client!(ComputeServiceClient<T>);

type ComputeMsgToNonce = HashMap<u16, [u8; 32]>;

#[async_trait(?Send)]
impl<T, U, V> Enigma2 for ComputeServiceClient<T, U, V>
where
    T: GrpcService<BoxBody> + Clone + Sync,
    T::Error: Into<StdError>,
    T::ResponseBody: Body<Data = Bytes> + Send + 'static,
    <T::ResponseBody as Body>::Error: Into<StdError> + Send,
    U: Enigma + Sync,
    V: Signer + Sync,
{
    async fn encrypt<M: Serialize + Send + Sync>(
        &self,
        contract_code_hash: &str,
        msg: &M,
    ) -> Result<SecretMsg> {
        self.encryption_utils
            .clone()
            .encrypt(contract_code_hash, msg)
            .await
            .map(|msg| SecretMsg::from(msg))
            .map_err(Into::into)
    }

    async fn decrypt(&self, nonce: &[u8; 32], ciphertext: &[u8]) -> Result<Vec<u8>> {
        self.encryption_utils
            .decrypt(nonce, ciphertext)
            .await
            .map_err(Into::into)
    }

    async fn decrypt_tx_response<'a>(
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

                    if let Ok(plaintext) = self.decrypt(&nonce, ciphertext).await {
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

                    if let Ok(plaintext) = self.decrypt(&nonce, ciphertext).await {
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

                    if let Ok(plaintext) = self.decrypt(&nonce, ciphertext).await {
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

                        if let Ok(bytes) = self.decrypt(nonce, &decoded.data).await {
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

                        if let Ok(bytes) = self.decrypt(nonce, &decoded.data).await {
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
                        if let Ok(bytes) = self.decrypt(nonce, &decoded.data).await {
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
impl<U, V> ComputeServiceClient<::tonic::transport::Channel, U, V>
where
    U: Enigma + Sync,
    V: Signer + Sync,
{
    pub async fn connect(options: CreateTxSenderOptions<U, V>) -> Result<Self> {
        let channel = tonic::transport::Channel::from_static(options.url)
            .connect()
            .await?;
        Ok(Self::new(channel, options))
    }
    pub fn new(channel: ::tonic::transport::Channel, options: CreateTxSenderOptions<U, V>) -> Self {
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
impl<U: Enigma + Sync, V: Signer + Sync>
    ComputeServiceClient<::tonic_web_wasm_client::Client, U, V>
{
    pub fn new(
        client: ::tonic_web_wasm_client::Client,
        options: CreateTxSenderOptions<U, V>,
    ) -> Self {
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

impl<T, U, V> ComputeServiceClient<T, U, V>
where
    T: GrpcService<BoxBody> + Clone + Sync,
    T::Error: Into<StdError>,
    T::ResponseBody: Body<Data = Bytes> + Send + 'static,
    <T::ResponseBody as Body>::Error: Into<StdError> + Send,
    U: Enigma + Sync,
    V: Signer + Sync,
{
    pub async fn store_code(&self, msg: MsgStoreCode, tx_options: TxOptions) -> Result<TxResponse> {
        self.sign_and_broadcast(vec![msg], tx_options).await
    }

    pub async fn instantiate_contract<M: Serialize + Send + Sync + std::fmt::Debug>(
        &self,
        msg: MsgInstantiateContract,
        code_hash: impl Into<String>,
        tx_options: TxOptions,
    ) -> Result<TxResponse> {
        self.sign_and_broadcast(vec![msg], tx_options).await
    }

    pub async fn execute_contract<M: Serialize + Send + Sync + std::fmt::Debug>(
        &self,
        // maybe instead of this, take in a "params" struct? or each part individually?
        msg: MsgExecuteContractRaw<M>,
        code_hash: impl Into<String>,
        tx_options: TxOptions,
    ) -> Result<TxResponse> {
        debug!("{}", serde_json::to_string_pretty(&msg.msg).unwrap());

        let encrypted_msg = self.encrypt(&code_hash.into(), &msg.msg).await?;

        let msg = MsgExecuteContract {
            msg: encrypted_msg.into_inner(),
            ..msg.into()
        };

        self.sign_and_broadcast(vec![msg], tx_options).await
    }

    pub async fn migrate_contract<M: Serialize + Send + Sync + std::fmt::Debug>(
        &self,
        msg: MsgMigrateContract,
        code_hash: impl Into<String>,
        tx_options: TxOptions,
    ) -> Result<TxResponse> {
        debug!("{}", serde_json::to_string_pretty(&msg.msg).unwrap());

        let encrypted_msg = self.encrypt(&code_hash.into(), &msg.msg).await?;

        let msg = MsgMigrateContract {
            msg: encrypted_msg.into_inner(),
            ..msg.into()
        };

        self.sign_and_broadcast(vec![msg], tx_options).await
    }
    pub async fn update_admin() {
        todo!()
    }
    pub async fn clear_admin() {
        todo!()
    }

    /// Broadcasts a signed transaction to the network and monitors its inclusion in a block.
    ///
    /// If broadcasting is rejected by the node for some reason (e.g. because of a CheckTx failure),
    /// an error is thrown.
    ///
    /// If the transaction is not included in a block before the provided timeout, this errors with a `TimeoutError`.
    ///
    /// If the transaction is included in a block, a [`TxResponse`] is returned. The caller then
    /// usually needs to check for execution success or failure.
    async fn broadcast_tx(
        &self,
        tx_bytes: Vec<u8>,
        timeout_ms: u32,
        check_interval_ms: u32,
        mut mode: BroadcastMode,
        wait_for_commit: bool,
        ibc_tx_options: Option<IbcTxOptions>,
    ) -> Result<TxResponse> {
        let start = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_millis();

        let mut hasher = Sha256::new();
        hasher.update(&tx_bytes);
        let hash = hasher.finalize();

        let tx = TxPb::decode(tx_bytes.as_ref())?;
        let txhash = hex::encode(hash).to_uppercase();

        if !wait_for_commit && mode == BroadcastMode::Block {
            mode = BroadcastMode::Sync
        }

        if mode == BroadcastMode::Block {
            let wait_for_commit = true;
            let is_broadcast_timed_out = false;

            let request = BroadcastTxRequest {
                tx_bytes,
                mode: mode.into(),
            };

            let mut tx_service = self.inner.clone();
            let BroadcastTxResponse { tx_response } =
                tx_service.broadcast_tx(request).await?.into_inner();

            let mut tx_response: TxResponseProto =
                tx_response.ok_or("Missing field 'tx_response'")?;
            tx_response.tx = Any::from_msg(&tx).ok();

            let tx_response: TxResponse = self.decode_tx_response(tx_response, None)?;
        }

        todo!()
    }

    async fn sign_and_broadcast<
        S: Serialize + DeserializeOwned + Send + Sync,
        M: Msg + ToAmino<S>,
    >(
        &self,
        messages: Vec<M>,
        tx_options: TxOptions,
    ) -> Result<TxResponse> {
        let tx_bytes = self
            .prepare_and_sign(messages, tx_options.clone())
            .await?
            .to_bytes()?;

        self.broadcast_tx(
            tx_bytes,
            tx_options.broadcast_timeout_ms,
            tx_options.broadcast_check_interval_ms,
            tx_options.broadcast_mode,
            tx_options.wait_for_commit,
            tx_options.ibc_txs_options,
        )
        .await
    }

    async fn prepare_and_sign<
        S: Serialize + DeserializeOwned + Send + Sync,
        M: Msg + ToAmino<S>,
    >(
        &self,
        messages: Vec<M>,
        tx_options: TxOptions,
    ) -> Result<Vec<u8>> {
        let memo = tx_options.memo;
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

        Ok(tx_bytes)
        // Ok(BroadcastTxRequest { tx_bytes, mode: 1 })
    }

    /// Gets account number and sequence from the API, creates a sign doc,
    /// creates a single signature and assembles the signed transaction.
    ///
    /// The sign mode (SIGN_MODE_DIRECT or SIGN_MODE_LEGACY_AMINO_JSON) is determined by this client's signer.
    ///
    /// You can pass signer data (account number, sequence and chain ID) explicitly instead of querying them
    /// from the chain. This is needed when signing for a multisig account, but it also allows for offline signing.
    async fn sign<S: Serialize + DeserializeOwned + Send + Sync, M: Msg + ToAmino<S>>(
        &self,
        messages: Vec<M>,
        fee: StdFee,
        memo: String,
        explicit_signer_data: Option<SignerData>,
    ) -> Result<TxRaw> {
        let signer = self.wallet.as_ref();
        let signer_address = self.wallet_address.as_ref();

        // All this to make sure the account matches the one given when the client was created.
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

        let signer_data = if let Some(signer_data) = explicit_signer_data {
            signer_data
        } else {
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
                .ok_or("Failed to retrieve and parse block height")?;

            let account: BaseAccount = response
                .account
                .and_then(|any| any.to_msg::<BaseAccount>().ok())
                .ok_or("No account found")?;

            let signer_data = SignerData {
                account_number: account.account_number,
                account_sequence: account.sequence,
                chain_id: self.chain_id.to_string(),
            };

            signer_data
        };

        match signer.get_sign_mode().await? {
            SignMode::Direct => {
                self.sign_direct(account_from_signer, messages, fee, memo, signer_data)
                    .await
            }
            SignMode::LegacyAminoJson => {
                self.sign_amino(account_from_signer, messages, fee, memo, signer_data)
                    .await
            }
            mode @ _ => Err(Error::SignMode(mode.as_str_name())),
        }
    }

    async fn sign_amino<S: Serialize + DeserializeOwned + Send + Sync, M: Msg + ToAmino<S>>(
        &self,
        account: AccountData,
        messages: Vec<M>,
        fee: StdFee,
        memo: String,
        signer_data: SignerData,
    ) -> Result<TxRaw> {
        // TODO: avoid having to make this check all over the place?
        let sign_mode = self.wallet.get_sign_mode().await?;

        let SignMode::LegacyAminoJson = sign_mode else {
            return Err(crate::Error::custom(
                "Wrong signer type! Expected AminoSigner or AminoEip191Signer.",
            ));
        };

        let amino_msgs: Vec<AminoMsg<S>> = messages.iter().map(|msg| msg.to_amino()).collect();

        let sign_doc = StdSignDoc {
            chain_id: self.chain_id.to_string(),
            account_number: signer_data.account_number.to_string(),
            sequence: signer_data.account_sequence.to_string(),
            fee,
            msgs: amino_msgs,
            memo,
        };

        let response: AminoSignResponse<S> =
            self.wallet.sign_amino(&account.address, sign_doc).await?;
        debug!("{:?}", serde_json::to_string(&response));

        let signed: StdSignDoc<S> = response.signed;
        let signature: StdSignature = response.signature;
        let signature_bytes = BASE64_STANDARD.decode(signature.signature)?;

        let messages: Vec<Any> = messages
            .iter()
            .map(|msg| msg.to_any().map_err(Error::custom))
            .collect::<Result<Vec<Any>>>()?;

        // TODO: use current block height + something? (If that's supported)
        let timeout_height = 0u32;
        let tx_body = TxBody::new(messages, signed.memo, timeout_height);

        let public_key: secretrs::crypto::PublicKey =
            secretrs::tendermint::PublicKey::from_raw_secp256k1(&account.pubkey.clone())
                .ok_or("Invalid raw secp256k1 key bytes")?
                .into();

        let signer_info = SignerInfo {
            public_key: Some(public_key).map(Into::into),
            mode_info: ModeInfo::single(SignMode::LegacyAminoJson),
            sequence: signed.sequence.parse::<u64>()?,
        };
        let auth_info = signer_info.auth_info(Fee::from_amount_and_gas(
            signed
                .fee
                .amount
                .first()
                .ok_or("Empty Vec<Coin>!")?
                .to_owned(),
            signed.fee.gas.parse::<u64>()?,
        ));
        // let sign_doc = SignDoc::new(
        //     &tx_body,
        //     &auth_info,
        //     &self.chain_id.parse()?,
        //     signer_data.account_number,
        // )?;

        debug!("{:?}", tx_body);
        debug!("{:?}", auth_info);

        let signed_tx_raw = TxRaw {
            body_bytes: tx_body.into_bytes()?,
            auth_info_bytes: auth_info.into_bytes()?,
            signatures: vec![signature_bytes],
        };

        Ok(signed_tx_raw)
    }

    async fn sign_direct(
        &self,
        account: AccountData,
        messages: Vec<impl Msg>,
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
    async fn populate_code_hash<M: Msg>(&self, msg: M) {
        todo!()
    }

    async fn perform(
        &self,
        request: BroadcastTxRequest,
    ) -> ::tonic::Result<::tonic::Response<BroadcastTxResponse>, ::tonic::Status> {
        self.inner.clone().broadcast_tx(request).await
    }
}

#[derive(Debug, Clone)]
/// MsgExecuteContract execute a contract handle function
pub struct MsgExecuteContractRaw<M>
where
    M: Serialize,
{
    /// Sender is the that actor that signed the messages
    pub sender: AccountId,

    /// The contract instance to execute the message on
    pub contract: AccountId,

    /// The message to pass to the contract handle method
    pub msg: M,

    /// Native amounts of coins to send with this message
    pub sent_funds: Vec<Coin>,
}

impl<M: Serialize> From<MsgExecuteContractRaw<M>> for MsgExecuteContract {
    fn from(value: MsgExecuteContractRaw<M>) -> Self {
        Self {
            sender: value.sender,
            contract: value.contract,
            msg: serde_json::to_vec(&value.msg).unwrap(),
            sent_funds: value.sent_funds,
        }
    }
}
