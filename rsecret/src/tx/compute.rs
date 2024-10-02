use super::{Error, Result};
use crate::{
    query::auth::{AuthQuerier, BaseAccount, QueryAccountRequest},
    secret_network_client::{
        CreateClientOptions, CreateTxSenderOptions, Enigma2, SignerData, TxOptions, TxResponse,
    },
    traits::{is_plaintext, ToAmino},
    wallet::{
        wallet_amino::{AminoMsg, AminoSignResponse, StdFee, StdSignDoc},
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
    tx::{Body as TxBody, BodyBuilder, Fee, Msg, Raw, SignDoc, SignMode, SignerInfo, Tx},
    utils::encryption::{EncryptionUtils, Enigma, SecretMsg},
    AccountId, Any, Coin,
};
use serde::{Deserialize, Serialize};
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
impl<T, U, V> crate::secret_network_client::Enigma2 for ComputeServiceClient<T, U, V>
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
impl<U: Enigma, V: Signer> ComputeServiceClient<::tonic_web_wasm_client::Client, U, V> {
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
        is_plaintext(&msg.init_msg)?;

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
        debug!("input msg: {:?}", msg);

        is_plaintext(&msg.msg)?;

        let encrypted_msg = self.encrypt(code_hash.into().as_ref(), &msg.msg).await?;

        let msg = MsgExecuteContract {
            msg: encrypted_msg.into_inner(),
            ..msg
        };
        debug!("encrypted msg: {:?}", msg);

        let tx_request = self.prepare_and_sign(vec![msg], tx_options).await?;
        let tx_response = self
            .perform(tx_request)
            .await?
            .into_inner()
            .tx_response
            .ok_or("no response")?;

        Ok(tx_response)
    }

    pub async fn migrate_contract(
        &self,
        msg: MsgExecuteContract,
        code_hash: impl Into<String>,
        tx_options: TxOptions,
    ) -> Result<TxResponseProto> {
        is_plaintext(&msg.msg)?;

        todo!()
    }
    pub async fn update_admin() {
        todo!()
    }
    pub async fn clear_admin() {
        todo!()
    }

    async fn prepare_and_sign<M: Msg + ToAmino>(
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
        messages: Vec<impl Msg + ToAmino>,
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
        messages: Vec<impl Msg + ToAmino>,
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

        // TODO:
        // 4) construct the tx_body, auth_info, etc using a mashup of the original messages, but
        //    the returned signed SignDoc for things like gas and memo changes
        // 5) turn all that into a TxRaw

        let amino_msgs: Vec<AminoMsg> = messages.iter().map(|msg| msg.to_amino()).collect();

        let serialized = serde_json::to_string(&amino_msgs).unwrap();
        debug!("Serialized AminoMsg: {}", serialized);

        let sign_doc = StdSignDoc {
            chain_id: self.chain_id.to_string(),
            account_number: signer_data.account_number.to_string(),
            sequence: signer_data.account_sequence.to_string(),
            fee,
            msgs: amino_msgs,
            memo,
        };

        let response: AminoSignResponse =
            self.wallet.sign_amino(&account.address, sign_doc).await?;

        let signed: StdSignDoc = response.signed;
        let signature = BASE64_STANDARD.decode(response.signature.signature)?;

        let messages: Vec<Any> = messages
            .iter()
            .map(|msg| msg.to_any().map_err(crate::Error::custom))
            .collect::<Result<Vec<Any>>>()?;

        let timeout_height = 1u32;
        let tx_body = TxBody::new(messages, signed.memo, timeout_height);

        let public_key: PublicKey =
            secretrs::tendermint::PublicKey::from_raw_secp256k1(&account.pubkey.clone())
                .expect("invalid raw secp256k1 key bytes")
                .into();

        let signer_info = SignerInfo::single_direct(Some(public_key), signer_data.account_sequence);
        let auth_info = signer_info.auth_info(Fee::from_amount_and_gas(
            signed
                .fee
                .amount
                .first()
                .expect("empty Vec<Coin>")
                .to_owned(),
            signed.fee.gas.parse::<u64>()?,
        ));
        let sign_doc = SignDoc::new(
            &tx_body,
            &auth_info,
            &self.chain_id.parse()?,
            signer_data.account_number,
        )?;

        let signed_tx_raw = TxRaw {
            body_bytes: tx_body.into_bytes()?,
            auth_info_bytes: auth_info.into_bytes()?,
            signatures: vec![signature],
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

#[derive(Serialize, Deserialize, Debug)]
pub struct MsgInstantiateContractParams {
    /// The actor that signed the messages
    pub sender: String,
    /// The id of the contract's WASM code
    pub code_id: CodeId,
    /// A unique label across all contracts
    pub label: String,
    /// The input message to the contract's constructor
    pub init_msg: serde_json::Value,
    /// Funds to send to the contract
    #[serde(skip_serializing_if = "Option::is_none")]
    pub init_funds: Option<Vec<Coin>>,
    /// The SHA256 hash value of the contract's WASM bytecode
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code_hash: Option<String>,
    /// Admin is an optional address that can execute migrations
    #[serde(skip_serializing_if = "Option::is_none")]
    pub admin: Option<String>,
}

// This enum can handle both `number` and `string` for `code_id`
#[derive(Serialize, Deserialize, Debug)]
#[serde(untagged)]
pub enum CodeId {
    Number(u64),
    String(String),
}

// #[derive(Debug, Serialize, Deserialize)]
// pub struct MsgInstantiateContract {
//     pub sender: String,
//     pub code_id: String,
//     pub label: String,
//     pub init_msg: serde_json::Value, // object in TypeScript can be serde_json::Value in Rust
//     pub init_funds: Vec<Coin>,
//     pub code_hash: String,
//     pub admin: Option<String>, // Optional field
//
//     // Fields that are not public
//     init_msg_encrypted: Option<Vec<u8>>, // Uint8Array in TypeScript is Vec<u8> in Rust
//     warn_code_hash: bool,
// }
//
// // Implementing functions (similar to the constructor and methods in the TypeScript class)
// impl MsgInstantiateContract {
//     // Constructor method
//     pub fn new(params: MsgInstantiateContractParams) -> Self {
//         MsgInstantiateContract {
//             sender: params.sender,
//             code_id: match params.code_id {
//                 CodeId::Number(n) => n.to_string(), // Handle number or string for code_id
//                 CodeId::String(s) => s,
//             },
//             label: params.label,
//             init_msg: params.init_msg,
//             init_funds: params.init_funds.unwrap_or_default(), // Default to an empty vector
//             code_hash: params.code_hash.unwrap_or_default(),
//             admin: params.admin,
//
//             // Private fields
//             init_msg_encrypted: None,
//             warn_code_hash: false, // Default value in TypeScript
//         }
//     }
//
//     // You can add other methods as needed to match the class functionality
//     pub fn set_warn_code_hash(&mut self, value: bool) {
//         self.warn_code_hash = value;
//     }
//
//     pub fn encrypt_init_msg(&mut self, encrypted_msg: Vec<u8>) {
//         self.init_msg_encrypted = Some(encrypted_msg);
//     }
// }
