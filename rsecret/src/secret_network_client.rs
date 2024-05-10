#![allow(unused)]

use hex::decode;
use log::{debug, info, trace, warn};
use serde::Deserialize;

use crate::{
    query::Querier,
    tx::TxSender,
    wallet::{
        wallet_amino::{AccountData, AminoSignResponse, AminoSigner, StdFee, StdSignDoc},
        wallet_proto::Wallet,
    },
    Error, Result,
};
use async_trait::async_trait;
use base64::prelude::{Engine as _, BASE64_STANDARD};
use prost::Message;
use secretrs::{
    abci::TxMsgData,
    proto::{
        cosmos::{
            base::abci::v1beta1::{
                AbciMessageLog, MsgData, TxMsgData as TxMsgDataProto, TxResponse as TxResponseProto,
            },
            tx::v1beta1::{
                BroadcastMode, GetTxResponse, OrderBy, SimulateResponse, Tx as TxProto, TxRaw,
            },
        },
        secret::compute::v1beta1::{
            MsgExecuteContract, MsgExecuteContractResponse, MsgInstantiateContract,
            MsgInstantiateContractResponse, MsgMigrateContract, MsgMigrateContractResponse,
        },
        tendermint::abci::Event as EventProto,
    },
    query::PageRequest,
    tendermint::abci::Event,
    tx::{
        AccountNumber, AuthInfo, Body as TxBody, BodyBuilder, Fee, MessageExt, Msg, Raw,
        SequenceNumber, SignDoc, SignatureBytes, SignerInfo, SignerPublicKey, Tx,
    },
    Any, EncryptionUtils,
};
use std::{collections::HashMap, str::FromStr, sync::Arc, time::Duration};
use tonic::codegen::{Body, Bytes, StdError};

#[derive(Debug)]
pub struct CreateClientOptions {
    /// A URL to the API service, also known as LCD, REST API or gRPC-gateway, typically on port 1317.
    pub url: &'static str,
    /// The chain-id used in encryption code & when signing transactions.
    pub chain_id: &'static str,
    /// An optional wallet for signing transactions & permits. If `wallet` is supplied,
    /// `wallet_address` must also be supplied.
    pub wallet: Option<Wallet>,
    /// The specific account address in the wallet that is permitted to sign transactions & permits.
    pub wallet_address: Option<String>,
    /// Optional encryption seed that will allow transaction decryption at a later time.
    /// Ignored if `encryption_utils` is supplied. Must be 32 bytes.
    pub encryption_seed: Option<[u8; 32]>,
    /// Optional field to override the default encryption utilities implementation.
    pub encryption_utils: Option<EncryptionUtils>,
}

impl Default for CreateClientOptions {
    fn default() -> Self {
        Self {
            url: "http://localhost:9090",
            chain_id: "secretdev-1",
            wallet: None,
            wallet_address: None,
            encryption_seed: None,
            encryption_utils: None,
        }
    }
}

impl CreateClientOptions {
    pub fn read_only(url: &'static str, chain_id: &'static str) -> Self {
        Self {
            url,
            chain_id,
            ..Default::default()
        }
    }
}

/// Options related to IBC transactions
#[derive(Debug, Clone)]
pub struct IbcTxOptions {
    /// If `false`, skip resolving the IBC response txs (acknowledge/timeout).
    ///
    /// Defaults to `true` when broadcasting a tx or using `getTx()`.
    /// Defaults to `false` when using `txsQuery()`.
    resolve_responses: bool,
    /// How much time (in milliseconds) to wait for IBC response txs (acknowledge/timeout).
    ///
    /// Defaults to `120_000` (2 minutes).
    resolve_responses_timeout_ms: u32,
    /// When waiting for the IBC response txs (acknowledge/timeout) to commit on-chain, how much time (in milliseconds) to wait between checks.
    ///
    /// Smaller intervals will cause more load on your node provider. Keep in mind that blocks on Secret Network take about 6 seconds to finalize.
    ///
    /// Defaults to `15_000` (15 seconds).
    resolve_responses_check_interval_ms: u32,
}

impl Default for IbcTxOptions {
    fn default() -> Self {
        Self {
            resolve_responses: true,
            resolve_responses_timeout_ms: 120_000,
            resolve_responses_check_interval_ms: 15_000,
        }
    }
}

/// Options for transactions
#[derive(Debug, Clone)]
pub struct TxOptions {
    /// Gas limit for the transaction, defaults to `50_000`
    pub gas_limit: u32,
    /// Gas price in fee denomination, defaults to `0.1`
    pub gas_price_in_fee_denom: f32,
    /// Denomination for the fee, defaults to `"uscrt"`
    pub fee_denom: String,
    /// Address of the fee granter
    pub fee_granter: Option<String>,
    /// Memo field of the transaction, defaults to an empty string `""`
    pub memo: String,
    /// Whether to wait for the transaction to commit, defaults to `true`
    pub wait_for_commit: bool,
    /// Timeout for waiting for the transaction to commit, defaults to `60_000` ms
    pub broadcast_timeout_ms: u32,
    /// Interval for checking the transaction commit status, defaults to `6_000` ms
    pub broadcast_check_interval_ms: u32,
    /// Broadcast mode, either synchronous or asynchronous
    pub broadcast_mode: BroadcastMode,
    /// Optional explicit signer data
    pub explicit_signer_data: Option<SignerData>,
    /// Options for resolving IBC ack/timeout transactions
    pub ibc_txs_options: Option<IbcTxOptions>,
}

impl Default for TxOptions {
    fn default() -> Self {
        Self {
            gas_limit: 50_000,
            gas_price_in_fee_denom: 0.1,
            fee_denom: "uscrt".to_string(),
            fee_granter: None,
            memo: String::default(),
            wait_for_commit: true,
            broadcast_timeout_ms: 60_000,
            broadcast_check_interval_ms: 6_000,
            broadcast_mode: BroadcastMode::Sync,
            explicit_signer_data: None,
            ibc_txs_options: Some(IbcTxOptions::default()),
        }
    }
}

/// Signer data for overriding chain-specific data
#[derive(Debug, Clone)]
pub struct SignerData {
    pub account_number: u32,
    pub account_sequence: u32,
    pub chain_id: String,
}

#[async_trait]
pub trait ReadonlySigner: AminoSigner {
    async fn get_accounts() -> Result<Vec<AccountData>> {
        Err("get_accounts() is not supported in readonly mode.".into())
    }
    async fn sign_amino(
        _signer_address: String,
        _sign_doc: StdSignDoc,
    ) -> Result<AminoSignResponse> {
        Err("sign_amino() is not supported in readonly mode.".into())
    }
}

// TODO: I am not sure if we need json_log or array_log, considering we have the typed "logs"
#[derive(Debug)]
pub struct TxResponse {
    /// Block height in which the tx was committed on-chain
    pub height: u64,
    /// Transaction hash (might be used as transaction ID). Guaranteed to be non-empty upper-case hex
    pub txhash: String,
    /// Namespace for the Code
    pub codespace: String,
    /// Transaction execution error code. 0 on success.
    pub code: u32,
    /// Return value (if there's any) for each input message
    pub data: Vec<MsgData>,
    /// The output of the application's logger (raw string). May be non-deterministic.
    ///
    /// If code != 0, rawLog contains the error.
    /// If code = 0 you'll probably want to use `jsonLog` or `arrayLog`.
    /// Values are not decrypted.
    pub raw_log: String,
    /// The output of the application's logger (typed). May be non-deterministic.
    pub logs: Vec<AbciMessageLog>,

    /// If code = 0, `jsonLog = serde_json::from_str(raw_log)`. Values are decrypted if possible.
    pub json_log: Option<JsonLog>,
    /// If code = 0, `array_log` is a flattened `json_log`. Values are decrypted if possible.
    pub array_log: Option<ArrayLog>,
    /// If code = 0 and the tx resulted in sending IBC packets, `ibc_ack_txs` is a list of IBC acknowledgement or timeout transactions which signal whether the original IBC packet was accepted, rejected, or timed-out on the receiving chain.
    pub ibc_responses: Option<Vec<IbcResponse>>,

    /// Additional information. May be non-deterministic.
    pub info: String,
    /// Gas limit that was originally set by the transaction.
    pub gas_wanted: u64,
    /// Amount of gas that was actually used by the transaction.
    pub gas_used: u64,
    /// Decoded transaction input.
    pub tx: Tx,
    /// Events defines all the events emitted by processing a transaction. Note,
    /// these events include those emitted by processing all the messages and those
    /// emitted from the ante handler. Whereas Logs contains the events, with
    /// additional metadata, emitted only by processing the messages.
    ///
    /// Note: events are not decrypted.
    pub events: Vec<Event>,
    /// An RFC 3339 timestamp of when the tx was committed on-chain.
    /// The format is `{year}-{month}-{day}T{hour}:{min}:{sec}[.{frac_sec}]Z`.
    pub timestamp: String,
}

#[derive(Debug, Default, Deserialize)]
pub struct JsonLogEntry {
    pub msg_index: u16,
    pub events: Vec<EventRaw>,
}

pub type JsonLog = Vec<JsonLogEntry>;

#[derive(Debug, Default, Deserialize)]
pub struct JsonLogEntryNoIndex {
    pub events: Vec<EventRaw>,
}

pub type JsonLogRaw = Vec<JsonLogEntryNoIndex>;

#[derive(Debug, Default, Deserialize)]
pub struct EventRaw {
    #[serde(rename = "type")]
    pub kind: String,
    pub attributes: Vec<EventAttribute>,
}

#[derive(Debug, Default, Deserialize)]
pub struct EventAttribute {
    pub key: String,
    pub value: String,
}

#[derive(Debug)]
pub struct ArrayLogEntry {
    pub msg: u32,
    pub r#type: String,
    pub key: String,
    pub value: String,
}

pub type ArrayLog = Vec<ArrayLogEntry>;

#[derive(Debug)]
pub enum IbcResponseType {
    Ack,
    Timeout,
}

#[derive(Debug)]
pub struct IbcResponse {
    pub r#type: IbcResponseType,
    pub tx: TxResponse,
}

impl IbcResponseType {
    pub fn from_str(s: &str) -> Option<IbcResponseType> {
        match s {
            "ack" => Some(IbcResponseType::Ack),
            "timeout" => Some(IbcResponseType::Timeout),
            _ => None,
        }
    }

    pub fn to_str(&self) -> &'static str {
        match self {
            IbcResponseType::Ack => "ack",
            IbcResponseType::Timeout => "timeout",
        }
    }
}

type ComputeMsgToNonce = HashMap<u16, [u8; 32]>;

#[derive(Debug)]
pub struct SecretNetworkClient<T>
where
    T: tonic::client::GrpcService<tonic::body::BoxBody>,
    T::Error: Into<StdError>,
    T::ResponseBody: Body<Data = Bytes> + Send + 'static,
    <T::ResponseBody as Body>::Error: Into<StdError> + Send,
    T: Clone,
{
    pub url: &'static str,
    pub query: Querier<T>,
    pub tx: TxSender<T>,
    pub wallet: Option<Wallet>,
    pub address: String,
    pub chain_id: &'static str,
    pub encryption_utils: EncryptionUtils,
    // TODO - is this worth doing?
    // tx_options: Arc<TxOptions>,
}

#[cfg(not(target_arch = "wasm32"))]
impl SecretNetworkClient<::tonic::transport::Channel> {
    pub async fn connect(options: CreateClientOptions) -> Result<Self> {
        let channel = tonic::transport::Channel::from_static(options.url)
            .concurrency_limit(32) // unsure what limit is appropriate
            .rate_limit(32, Duration::from_secs(1)) // 32 reqs/s seems reasonable
            .timeout(Duration::from_secs(6)) // server is not aware of this timeout; that ok?
            .connect()
            .await?;
        Ok(Self::new(channel, options)?)
    }

    pub fn new(channel: ::tonic::transport::Channel, options: CreateClientOptions) -> Result<Self> {
        let url = options.url;

        let query = Querier::new(channel.clone(), &options);
        let tx = TxSender::new(channel.clone(), &options);
        // let tx_options = Arc::new(TxOptions::default());

        let wallet = options.wallet;
        let address = options.wallet_address.unwrap_or_default();
        let chain_id = options.chain_id;

        let encryption_utils = EncryptionUtils::new(options.encryption_seed, options.chain_id)?;

        Ok(Self {
            url,
            query,
            tx,
            wallet,
            address,
            chain_id,
            encryption_utils,
        })
    }

    // I think it'd be a nice feature to be able to change the default tx options
    // pub fn tx_options(&mut self, options: TxOptions) -> &mut Self {
    //     self.tx_options = Arc::new(options);
    //     self
    // }
}

impl<T> SecretNetworkClient<T>
where
    T: tonic::client::GrpcService<tonic::body::BoxBody>,
    T::Error: Into<StdError>,
    T::ResponseBody: Body<Data = Bytes> + Send + 'static,
    <T::ResponseBody as Body>::Error: Into<StdError> + Send,
    T: Clone,
{
    /// Returns a transaction with a txhash. Must be 64 character upper-case hex string.
    pub async fn get_tx(
        &self,
        hash: &str,
        ibc_tx_options: Option<IbcTxOptions>,
    ) -> Result<Option<TxResponse>> {
        // TODO: check that get_tx() handles the "tx not found" error
        let get_tx_response = self.query.tx.get_tx(hash).await?;
        let Some(tx_response) = get_tx_response.tx_response else {
            return Ok(None);
        };
        let tx_response = self.decode_tx_response(tx_response, ibc_tx_options)?;

        Ok(Some(tx_response))
    }

    /// To tell which events you want, you need to provide a query. query is a string, which has a form: "condition AND condition ..." (no OR at the moment).
    ///
    /// condition has a form: "key operation operand". key is a string with a restricted set of possible symbols (\t\n\r\()"'=>< are not allowed).
    ///
    /// operation can be "=", "<", "<=", ">", ">=", "CONTAINS" AND "EXISTS". operand can be a string (escaped with single quotes), number, date or time.
    ///
    /// Examples:
    /// - `tx.hash='XYZ'` # single transaction
    /// - `tx.height=5` # all txs of the fifth block
    /// - `create_validator.validator='ABC'` # tx where validator ABC was created
    ///
    /// Tendermint provides a few predefined keys: `tm.event`, `tx.hash` and `tx.height`. You can provide additional event keys that were emitted during the transaction.
    ///
    /// All events are indexed by a composite key of the form `{eventType}.{evenAttrKey}`.
    ///
    /// Multiple event types with duplicate keys are allowed and are meant to categorize unique and distinct events.
    ///
    /// To create a query for txs where AddrA transferred funds: `transfer.sender='AddrA'`.
    ///
    /// NOTE: Starting from Cosmos SDK v0.46+, expressions cannot contain spaces anymore:
    /// - Legal: `a.b='c'`
    /// - Illegal: `a.b = 'c'`
    async fn txs_query(
        &self,
        query: String,
        ibc_tx_options: IbcTxOptions,
        pagination: PageRequest,
        order_by: OrderBy,
    ) -> Result<Vec<TxResponse>> {
        todo!()
    }

    async fn wait_for_ibc_response(
        &self,
        packet_sequence: &str,
        packet_src_channel: &str,
        r#type: IbcResponseType,
        ibc_tx_options: IbcTxOptions,
        // is_done_object: { isDone: boolean },
    ) -> Result<IbcResponse> {
        todo!()
    }

    fn decode_tx_responses(
        &self,
        tx_responses: Vec<TxResponseProto>,
        ibc_tx_options: Option<IbcTxOptions>,
    ) -> Result<Vec<TxResponse>> {
        tx_responses
            .into_iter()
            .map(|tx_response| self.decode_tx_response(tx_response, ibc_tx_options.clone()))
            .collect()
    }

    fn decode_tx_response(
        &self,
        tx_response: TxResponseProto,
        ibc_tx_options: Option<IbcTxOptions>,
    ) -> Result<TxResponse> {
        let explicit_ibc_tx_options = ibc_tx_options.unwrap_or_default();
        let mut nonces = ComputeMsgToNonce::new();

        let Some(any) = tx_response.tx else {
            return Err("missing field: 'tx'".into());
        };

        // We process `tx` first to extract the nonces from the original Tx messages
        let mut tx: Tx = any.to_msg::<TxProto>()?.try_into()?;

        for (msg_index, any) in tx.body.messages.iter_mut().enumerate() {
            // Check if the message needs decryption
            match any.type_url.as_str() {
                "/secret.compute.v1beta1.MsgInstantiateContract" => {
                    let mut msg = any.to_msg::<MsgInstantiateContract>()?;
                    let mut nonce = [0u8; 32];
                    nonce.copy_from_slice(&msg.init_msg[0..32]);
                    let ciphertext = &msg.init_msg[64..];

                    if let Ok(plaintext) = self.encryption_utils.decrypt(&nonce, ciphertext) {
                        nonces.insert(msg_index as u16, nonce);
                        msg.init_msg = serde_json::from_slice(&plaintext[64..])?;
                        *any = Any::from_msg::<MsgInstantiateContract>(&msg)?
                    }
                }
                "/secret.compute.v1beta1.MsgExecuteContract" => {
                    let mut msg = any.to_msg::<MsgExecuteContract>()?;
                    let mut nonce = [0u8; 32];
                    nonce.copy_from_slice(&msg.msg[0..32]);
                    let ciphertext = &msg.msg[64..];

                    if let Ok(plaintext) = self.encryption_utils.decrypt(&nonce, ciphertext) {
                        // we only insert the nonce in the hashmap if we were able to use it!
                        nonces.insert(msg_index as u16, nonce);
                        //hopefully these bytes are utf-8 string of valid JSON
                        msg.msg = serde_json::from_slice(&plaintext[64..])?;
                        debug!("decryption success! {:#?}", msg.msg);

                        *any = Any::from_msg::<MsgExecuteContract>(&msg)?
                    }
                    debug!("unable to decrypt... oh well!");
                }
                "/secret.compute.v1beta1.MsgMigrateContract" => {
                    let mut msg = any.to_msg::<MsgMigrateContract>()?;
                    let mut nonce = [0u8; 32];
                    nonce.copy_from_slice(&msg.msg[0..32]);
                    let ciphertext = &msg.msg[64..];

                    if let Ok(plaintext) = self.encryption_utils.decrypt(&nonce, ciphertext) {
                        nonces.insert(msg_index as u16, nonce);
                        msg.msg = serde_json::from_slice(&plaintext[64..])?;
                        *any = Any::from_msg::<MsgMigrateContract>(&msg)?
                    }
                }
                // If the message is not of type MsgInstantiateContract, MsgExecuteContract, or
                // MsgMigrateContract, leave it unchanged. It doesn't require any decryption.
                _ => {}
            };
        }

        let mut data =
            <TxMsgDataProto as Message>::decode(hex::decode(tx_response.data)?.as_ref())?;

        // NOTE: This part is confusing!
        // `TxMsgData` has two fields: `data: Vec<MsgData>` and `msg_responses: Vec<Any>`.
        //     * `data` was deprecated in v0.46, but secret is currently v0.45
        //     * `msg_responnses` is currently empty
        // `MsgData` is like a pseudo-Any. It has two fields: `msg_type: String` and `data: Vec<u8>`.
        //     * `msg_type` is the type of message that `data` is the response for

        #[allow(deprecated)]
        for (msg_index, msg_data) in data.data.iter_mut().enumerate() {
            // Check if the message needs decryption
            if let Some(nonce) = nonces.get(&(msg_index as u16)) {
                match msg_data.msg_type.as_str() {
                    // if the message was a MsgInstantiateContract, then the data is in the form of
                    // MsgInstantiateContractResponse. same goes for Execute and Migrate.
                    "/secret.compute.v1beta1.MsgInstantiateContract" => {
                        let mut decoded =
                            <MsgInstantiateContractResponse as Message>::decode(&*msg_data.data)?;

                        if let Ok(plaintext_bytes) =
                            self.encryption_utils.decrypt(&nonce, &decoded.data)
                        {
                            let plaintext_b64 = String::from_utf8(plaintext_bytes)?;
                            let data = BASE64_STANDARD.decode(plaintext_b64)?;

                            decoded.data = data;

                            *msg_data = MsgData {
                                msg_type: "/secret.compute.v1beta1.MsgInstantiateContract"
                                    .to_string(),
                                data: decoded.data,
                            }
                        }
                    }
                    "/secret.compute.v1beta1.MsgExecuteContract" => {
                        let mut decoded =
                            <MsgExecuteContractResponse as Message>::decode(&*msg_data.data)?;

                        if let Ok(plaintext_bytes) =
                            self.encryption_utils.decrypt(&nonce, &decoded.data)
                        {
                            let plaintext_b64 = String::from_utf8(plaintext_bytes)?;
                            let data = BASE64_STANDARD.decode(plaintext_b64)?;

                            decoded.data = data;

                            *msg_data = MsgData {
                                msg_type: "/secret.compute.v1beta1.MsgExecuteContract".to_string(),
                                data: decoded.data,
                            }
                        }
                        debug!("unable to decrypt... oh well!");
                    }
                    "/secret.compute.v1beta1.MsgMigrateContract" => {
                        let mut decoded =
                            <MsgMigrateContractResponse as Message>::decode(&*msg_data.data)?;

                        if let Ok(plaintext_bytes) =
                            self.encryption_utils.decrypt(&nonce, &decoded.data)
                        {
                            let plaintext_b64 = String::from_utf8(plaintext_bytes)?;
                            let data = BASE64_STANDARD.decode(plaintext_b64)?;

                            decoded.data = data;

                            *msg_data = MsgData {
                                msg_type: "/secret.compute.v1beta1.MsgMigrateContract".to_string(),
                                data: decoded.data,
                            }
                        }
                    }
                    // If the message is not of type MsgInstantiateContractResponse,
                    // MsgExecuteContractResponse, or MsgMigrateContractResponse,
                    // leave it unchanged. It doesn't require any decryption.
                    _ => {
                        debug!("no encrypted messages here!")
                    }
                };
            }
        }

        #[allow(deprecated)]
        let data = data.data;

        // TODO:
        // * Produce json_log and array_log from raw_log

        let mut json_log_raw = JsonLogRaw::default();
        let mut json_log = JsonLog::default();
        let mut array_log = ArrayLog::default();

        if tx_response.code == 0 && tx_response.raw_log != "" {
            // this mess takes the array of objects containing "events"
            // and adds another field "msg_index" to them.
            //
            // See https://github.com/cosmos/cosmos-sdk/pull/11147
            //
            // Ex:
            // [
            //   {
            //     "msg_index": 0  <--- ADDED FIELD
            //     "events": [
            //       {
            //         "type":"message",
            //         "attributes":[
            //           {"key":"action","value":"/ibc.core.client.v1.MsgUpdateClient"},
            //           {"key":"module","value":"ibc_client"}
            //         ]
            //       }
            //     ]
            //   }
            // ]
            json_log_raw = serde_json::from_str(&tx_response.raw_log)?;
            json_log = json_log_raw
                .into_iter()
                .enumerate()
                .map(|(msg_index, entry)| JsonLogEntry {
                    msg_index: msg_index as u16,
                    events: entry.events,
                })
                .collect();
        }

        let json_log = None;
        let array_log = None;
        let ibc_responses = None;

        let events = tx_response
            .events
            .into_iter()
            .map(|event| Ok(event.try_into()?))
            .collect::<Result<Vec<Event>>>()?;

        // The fields with shorthand struct initialization are the ones we modified
        Ok(TxResponse {
            height: tx_response.height as u64,
            txhash: tx_response.txhash.to_uppercase(),
            code: tx_response.code,
            codespace: tx_response.codespace,
            data,
            raw_log: tx_response.raw_log,
            logs: tx_response.logs,
            json_log,
            array_log,
            ibc_responses,
            info: tx_response.info,
            gas_wanted: tx_response.gas_wanted as u64,
            gas_used: tx_response.gas_used as u64,
            tx,
            timestamp: tx_response.timestamp,
            events,
        })
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
    async fn broadcast_tx<M: Msg>(
        &self,
        tx_bytes: Vec<u8>,
        timeout_ms: u32,
        check_interval_ms: u32,
        mode: BroadcastMode,
        wait_for_commit: bool,
        ibc_tx_options: IbcTxOptions,
    ) -> Result<TxResponse> {
        todo!()
    }

    /// Prepare and sign an array of messages as a transaction.
    async fn sign_tx<M: Msg>(&self, messages: Vec<M>, tx_options: TxOptions) -> Result<Vec<u8>> {
        todo!()
    }

    /// Broadcast a signed transaction.
    async fn broadcast_signed_tx(
        &self,
        tx_bytes: Vec<u8>,
        tx_options: TxOptions,
    ) -> Result<TxResponse> {
        todo!()
    }

    async fn prepare_and_sign<M: Msg>(
        &self,
        messages: Vec<M>,
        tx_options: TxOptions,
        simulate: bool,
    ) -> Result<Vec<u8>> {
        todo!()
    }

    async fn sign_and_broadcast<M: Msg>(
        &self,
        messages: Vec<M>,
        tx_options: TxOptions,
    ) -> Result<TxResponse> {
        todo!()
    }

    async fn simulate<M: Msg>(
        &self,
        messages: Vec<M>,
        tx_options: TxOptions,
    ) -> Result<SimulateResponse> {
        todo!()
    }

    /// Signs a transaction.
    ///
    /// Gets account number and sequence from the API, creates a sign doc, creates a single signature, and assembles the signed transaction.
    /// The sign mode (SIGN_MODE_DIRECT or SIGN_MODE_LEGACY_AMINO_JSON) is determined by this client's signer.
    ///
    /// You can pass signer data (account number, sequence and chain ID) explicitly instead of querying them
    /// from the chain. This is needed when signing for a multisig account, but it also allows for offline signing.
    async fn sign(
        // TODO: define a Msg type
        // messages: Vec<Msg>,
        fee: StdFee,
        memo: String,
        explicit_signer_data: SignerData,
        simulate: bool,
    ) -> Result<TxRaw> {
        todo!()
    }

    async fn sign_amino(&self) {
        todo!()
    }

    async fn populate_code_hash(&self) {
        todo!()
    }

    async fn encode_tx(&self) {
        todo!()
    }

    async fn sign_direct(&self) {
        todo!()
    }
}

// TODO: we needsome generic 'Msg' type to be used in all these methods.
// I think one exists in cosmrs... but that probably won't have a to_amino method
//
// pub struct ProtoMsg {
//     type_url: String,
//     // value is used in x/compute
//     value: Vec<u8>,
// }
//
// pub trait ProtoMsg {
//     async fn encode(&self) -> Result<Vec<u8>>;
// }
//
// pub struct AminoMsg {
//     r#type: String,
//     value: Vec<u8>,
// }
//
// pub trait Msg {
//     fn to_proto(utils: EncryptionUtils) -> Result<ProtoMsg>;
//     fn to_amino(utils: EncryptionUtils) -> Result<AminoMsg>;
// }

// TODO: work out traits related to signing
//
// /// A signer capable of signing transactions.
// pub trait Signer {
//     // Define methods relevant to the Signer trait here
//     fn sign();
// }
//
// pub trait DirectSigner: Signer {
//     fn sign_direct();
// }
//
// impl Signer for Wallet {
//     fn sign() {
//         todo!()
//     }
// }

/// SignDoc is the type used for generating sign bytes for SIGN_MODE_DIRECT.
#[derive(Debug, Clone)]
#[allow(non_snake_case)]
pub struct SignDocCamelCase {
    /// `bodyBytes` is protobuf serialization of a TxBody that matches the
    /// representation in TxRaw.
    pub bodyBytes: Vec<u8>,

    /// `authInfoBytes` is a protobuf serialization of an AuthInfo that matches the
    /// representation in TxRaw.
    pub authInfoBytes: Vec<u8>,

    /// `chainId` is the unique identifier of the chain this transaction targets.
    /// It prevents signed transactions from being used on another chain by an
    /// attacker.
    pub chainId: String,

    /// `accountNumber` is the account number of the account in state.
    pub accountNumber: String,
}

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TxResultCode {
    Success = 0,
    ErrInternal = 1,
    ErrTxDecode = 2,
    ErrInvalidSequence = 3,
    ErrUnauthorized = 4,
    ErrInsufficientFunds = 5,
    ErrUnknownRequest = 6,
    ErrInvalidAddress = 7,
    ErrInvalidPubKey = 8,
    ErrUnknownAddress = 9,
    ErrInvalidCoins = 10,
    ErrOutOfGas = 11,
    ErrMemoTooLarge = 12,
    ErrInsufficientFee = 13,
    ErrTooManySignatures = 14,
    ErrNoSignatures = 15,
    ErrJSONMarshal = 16,
    ErrJSONUnmarshal = 17,
    ErrInvalidRequest = 18,
    ErrTxInMempoolCache = 19,
    ErrMempoolIsFull = 20,
    ErrTxTooLarge = 21,
    ErrKeyNotFound = 22,
    ErrWrongPassword = 23,
    ErrorInvalidSigner = 24,
    ErrorInvalidGasAdjustment = 25,
    ErrInvalidHeight = 26,
    ErrInvalidVersion = 27,
    ErrInvalidChainID = 28,
    ErrInvalidType = 29,
    ErrTxTimeoutHeight = 30,
    ErrUnknownExtensionOptions = 31,
    ErrWrongSequence = 32,
    ErrPackAny = 33,
    ErrUnpackAny = 34,
    ErrLogic = 35,
    ErrConflict = 36,
    ErrNotSupported = 37,
    ErrNotFound = 38,
    ErrIO = 39,
    ErrAppConfig = 40,
    ErrPanic = 111222,
}

impl TxResultCode {
    pub fn from_code(code: u32) -> Option<Self> {
        match code {
            0 => Some(Self::Success),
            1 => Some(Self::ErrInternal),
            2 => Some(Self::ErrTxDecode),
            3 => Some(Self::ErrInvalidSequence),
            4 => Some(Self::ErrUnauthorized),
            5 => Some(Self::ErrInsufficientFunds),
            6 => Some(Self::ErrUnknownRequest),
            7 => Some(Self::ErrInvalidAddress),
            8 => Some(Self::ErrInvalidPubKey),
            9 => Some(Self::ErrUnknownAddress),
            10 => Some(Self::ErrInvalidCoins),
            11 => Some(Self::ErrOutOfGas),
            12 => Some(Self::ErrMemoTooLarge),
            13 => Some(Self::ErrInsufficientFee),
            14 => Some(Self::ErrTooManySignatures),
            15 => Some(Self::ErrNoSignatures),
            16 => Some(Self::ErrJSONMarshal),
            17 => Some(Self::ErrJSONUnmarshal),
            18 => Some(Self::ErrInvalidRequest),
            19 => Some(Self::ErrTxInMempoolCache),
            20 => Some(Self::ErrMempoolIsFull),
            21 => Some(Self::ErrTxTooLarge),
            22 => Some(Self::ErrKeyNotFound),
            23 => Some(Self::ErrWrongPassword),
            24 => Some(Self::ErrorInvalidSigner),
            25 => Some(Self::ErrorInvalidGasAdjustment),
            26 => Some(Self::ErrInvalidHeight),
            27 => Some(Self::ErrInvalidVersion),
            28 => Some(Self::ErrInvalidChainID),
            29 => Some(Self::ErrInvalidType),
            30 => Some(Self::ErrTxTimeoutHeight),
            31 => Some(Self::ErrUnknownExtensionOptions),
            32 => Some(Self::ErrWrongSequence),
            33 => Some(Self::ErrPackAny),
            34 => Some(Self::ErrUnpackAny),
            35 => Some(Self::ErrLogic),
            36 => Some(Self::ErrConflict),
            37 => Some(Self::ErrNotSupported),
            38 => Some(Self::ErrNotFound),
            39 => Some(Self::ErrIO),
            40 => Some(Self::ErrAppConfig),
            111222 => Some(Self::ErrPanic),
            _ => None,
        }
    }
}
