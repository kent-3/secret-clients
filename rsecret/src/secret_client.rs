#![allow(unused)]

pub mod to_amino;
pub use to_amino::ToAmino;

pub mod msg;

use crate::{
    query::Querier,
    tx::TxSender,
    wallet::{
        wallet_amino::{
            AccountData, AminoSignResponse, AminoWallet, StdFee, StdSignDoc, WalletOptions,
        },
        wallet_proto::Wallet,
        Signer,
    },
    Error, Result,
};
use async_trait::async_trait;
use base64::prelude::{Engine as _, BASE64_STANDARD};
use hex::decode;
use prost::Message;
use secretrs::{
    abci::{MsgData, TxMsgData},
    proto::{
        cosmos::{
            base::{
                abci::v1beta1::{
                    AbciMessageLog, MsgData as MsgDataProto, TxMsgData as TxMsgDataProto,
                    TxResponse as TxResponseProto,
                },
                query::v1beta1::PageRequest,
            },
            tx::v1beta1::{
                BroadcastMode, GetTxResponse, GetTxsEventRequest, OrderBy, SimulateRequest,
                SimulateResponse, Tx as TxProto, TxRaw,
            },
        },
        secret::compute::v1beta1::{
            MsgExecuteContract, MsgExecuteContractResponse, MsgInstantiateContract,
            MsgInstantiateContractResponse, MsgMigrateContract, MsgMigrateContractResponse,
        },
        tendermint::abci::Event as EventProto,
    },
    tendermint::abci::Event,
    tx::{
        AccountNumber, AuthInfo, Body as TxBody, BodyBuilder, Fee, MessageExt, Msg, Raw,
        SequenceNumber, SignDoc, SignatureBytes, SignerInfo, SignerPublicKey, Tx,
    },
    utils::encryption::{EnigmaUtils, SecretUtils},
    Any, Coin,
};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, str::FromStr, sync::Arc, time::Duration};
use tonic::{
    body::BoxBody,
    client::GrpcService,
    codegen::{Body, Bytes, StdError},
};
use tracing::{debug, error, info, trace, warn};

#[cfg(not(target_arch = "wasm32"))]
use tonic::transport::ClientTlsConfig;

#[derive(Debug)]
pub struct SecretNetworkClientBuilder<S>
where
    S: Signer,
{
    url: Option<&'static str>,
    chain_id: Option<&'static str>,
    wallet: Option<Arc<S>>,
    wallet_address: Option<String>,
    encryption_seed: Option<[u8; 32]>,
    enigma_utils: Option<EnigmaUtils>,
}

#[derive(Debug)]
pub struct CreateClientOptions<U, V>
where
    U: SecretUtils,
    V: Signer,
{
    /// A URL to the API service, also known as LCD, REST API or gRPC-gateway, typically on port 1317.
    pub url: &'static str,
    /// The chain-id used in encryption code & when signing transactions.
    pub chain_id: &'static str,
    /// An optional wallet for signing transactions & permits. If `wallet` is supplied,
    /// `wallet_address` must also be supplied.
    pub wallet: Option<V>,
    /// The specific account address in the wallet that is permitted to sign transactions & permits.
    pub wallet_address: Option<String>,
    /// Optional encryption seed that will allow transaction decryption at a later time.
    /// Ignored if `enigma_utils` is supplied. Must be 32 bytes.
    pub encryption_seed: Option<[u8; 32]>,
    /// Optional field to override the default encryption utilities implementation.
    pub enigma_utils: Option<U>,
}

impl<U, V> Default for CreateClientOptions<U, V>
where
    U: SecretUtils,
    V: Signer,
{
    fn default() -> Self {
        Self {
            url: "http://localhost:9090",
            chain_id: "secretdev-1",
            wallet: None,
            wallet_address: None,
            encryption_seed: None,
            enigma_utils: None,
        }
    }
}

impl<U, V> CreateClientOptions<U, V>
where
    U: SecretUtils,
    V: Signer,
{
    pub fn read_only(url: &'static str, chain_id: &'static str) -> Self {
        Self {
            url,
            chain_id,
            ..Default::default()
        }
    }
}

// NOTE: these technically don't require the chain_id, because the EnigmaUtils are provided,
// but I'll leave it here just in case.

// TODO: bad design when a Channel or Client is provided (they already have a URL)
#[derive(Debug, Clone)]
pub struct CreateQuerierOptions<T: SecretUtils> {
    pub url: &'static str,
    pub chain_id: &'static str,
    pub enigma_utils: Arc<T>,
}

#[derive(Debug, Clone)]
pub struct CreateTxSenderOptions<T, U>
where
    T: SecretUtils,
    U: Signer,
{
    pub url: &'static str,
    pub chain_id: &'static str,
    pub enigma_utils: Arc<T>,
    pub wallet: Arc<U>,
    pub wallet_address: Arc<str>,
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
    pub account_number: u64,
    pub account_sequence: u64,
    pub chain_id: String,
}

#[async_trait]
pub trait ReadonlySigner: Signer {
    async fn get_accounts() -> Result<Vec<AccountData>> {
        Err("get_accounts() is not supported in readonly mode.".into())
    }
    async fn sign_amino<T: Serialize + Send + Sync + 'static>(
        _signer_address: String,
        _sign_doc: StdSignDoc<T>,
    ) -> Result<AminoSignResponse<T>> {
        Err("sign_amino() is not supported in readonly mode.".into())
    }
}

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
    /// If code = 0, see `logs` instead.
    /// Values are not decrypted.
    pub raw_log: String,
    /// The output of the application's logger (typed). May be non-deterministic.
    /// Values are decrypted when possible.
    pub logs: Vec<AbciMessageLog>,
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

trait ReadWrite {}

impl<T, U, S> ReadWrite for TxSender<T, U, S>
where
    T: GrpcService<BoxBody> + Clone + Sync,
    T::Error: Into<StdError>,
    T::ResponseBody: Body<Data = Bytes> + Send + 'static,
    <T::ResponseBody as Body>::Error: Into<StdError> + Send,
    U: SecretUtils + Sync,
    S: Signer + Sync,
{
}

impl<S> ReadWrite for Arc<S> {}

#[derive(Debug)]
pub struct SecretNetworkClient<T, U, V>
where
    T: GrpcService<BoxBody> + Clone + Sync,
    T::Error: Into<StdError>,
    T::ResponseBody: Body<Data = Bytes> + Send + 'static,
    <T::ResponseBody as Body>::Error: Into<StdError> + Send,
    U: SecretUtils + Sync,
    V: Signer + Sync,
{
    pub url: String,
    pub chain_id: String,
    pub enigma_utils: Arc<U>,
    pub query: Querier<T, U>,
    pub tx: TxSender<T, U, V>,
    pub wallet: Arc<V>,
    pub address: String,
    // TODO - is this worth doing?
    // tx_options: Arc<TxOptions>,
}

#[cfg(not(target_arch = "wasm32"))]
impl<U: SecretUtils + Sync, V: Signer + Sync>
    SecretNetworkClient<::tonic::transport::Channel, U, V>
{
    pub async fn connect(options: CreateClientOptions<U, V>) -> Result<Self> {
        let tls = ClientTlsConfig::new().with_webpki_roots();
        let channel = tonic::transport::Channel::from_static(options.url)
            .tls_config(tls)?
            .concurrency_limit(1) // unsure what limit is appropriate
            .rate_limit(1, Duration::from_secs(1)) // 1 req/s
            .timeout(Duration::from_secs(6)) // server is not aware of this timeout; that ok?
            .connect()
            .await?;
        Self::new(channel, options)
    }

    pub fn new(
        channel: ::tonic::transport::Channel,
        options: CreateClientOptions<U, V>,
    ) -> Result<Self> {
        // FIXME: bad API. I should be able to create a read-only client if no signer is given.
        let wallet = Arc::new(options.wallet.expect("Wallet should be provided"));

        let enigma_utils = Arc::new(
            options
                .enigma_utils
                .expect("EnigmaUtils should be provided"),
        );

        // // if no EnigmaUtils is provided, one is created
        // let enigma_utils = options.enigma_utils.unwrap_or_else(|| {
        //     // if no seed is provided, one is randomly generated
        //     // TODO: query the chain for the enclave IO pubkey
        //     EnigmaUtils::new(options.encryption_seed, options.chain_id).unwrap()
        // });

        // let query_client_options = CreateQuerierOptions {
        //     url: options.url,
        //     chain_id: options.chain_id,
        //     enigma_utils: enigma_utils.clone(),
        // };
        let query = Querier::new(channel.clone(), enigma_utils.clone());

        let tx_client_options = CreateTxSenderOptions {
            url: options.url,
            chain_id: options.chain_id,
            wallet: wallet.clone(),
            wallet_address: options.wallet_address.clone().unwrap_or_default().into(),
            enigma_utils: enigma_utils.clone(),
        };
        let tx = TxSender::new(channel.clone(), tx_client_options);

        Ok(Self {
            url: options.url.into(),
            query,
            tx,
            wallet,
            address: options.wallet_address.unwrap_or_default(),
            chain_id: options.chain_id.into(),
            enigma_utils,
        })
    }

    // I think it'd be a nice feature to be able to change the default tx options
    // pub fn tx_options(&mut self, options: TxOptions) -> &mut Self {
    //     self.tx_options = Arc::new(options);
    //     self
    // }
}

#[cfg(not(target_arch = "wasm32"))]
impl<U: SecretUtils + Sync> SecretNetworkClient<::tonic::transport::Channel, U, Wallet> {
    pub fn new_wallet(
        channel: ::tonic::transport::Channel,
        options: CreateClientOptions<U, Wallet>,
    ) -> Result<Self> {
        // if no Wallet is provided, a random one is created
        let wallet = Arc::new(options.wallet.unwrap_or_else(|| {
            Wallet::new(AminoWallet::new(None, WalletOptions::default()).unwrap())
        }));

        let enigma_utils = Arc::new(options.enigma_utils.expect("must provide enigma_utils"));

        // // if no EnigmaUtils is provided, one is created
        // let enigma_utils = options.enigma_utils.unwrap_or_else(|| {
        //     // if no seed is provided, one is randomly generated
        //     // TODO: query the chain for the enclave IO pubkey
        //     EnigmaUtils::new(options.encryption_seed, options.chain_id).unwrap()
        // });

        // let query_client_options = CreateQuerierOptions {
        //     url: options.url,
        //     chain_id: options.chain_id,
        //     enigma_utils: enigma_utils.clone(),
        // };
        let query = Querier::new(channel.clone(), enigma_utils.clone());

        let tx_client_options = CreateTxSenderOptions {
            url: options.url,
            chain_id: options.chain_id,
            wallet: wallet.clone(),
            wallet_address: options.wallet_address.clone().unwrap_or_default().into(),
            enigma_utils: enigma_utils.clone(),
        };
        let tx = TxSender::new(channel.clone(), tx_client_options);

        Ok(Self {
            url: options.url.into(),
            query,
            tx,
            wallet,
            address: options.wallet_address.unwrap_or_default(),
            chain_id: options.chain_id.into(),
            enigma_utils,
        })
    }

    // I think it'd be a nice feature to be able to change the default tx options
    // pub fn tx_options(&mut self, options: TxOptions) -> &mut Self {
    //     self.tx_options = Arc::new(options);
    //     self
    // }
}
#[cfg(target_arch = "wasm32")]
impl<U: SecretUtils + Sync, V: Signer + Sync>
    SecretNetworkClient<::tonic_web_wasm_client::Client, U, V>
{
    pub fn new(
        client: ::tonic_web_wasm_client::Client,
        options: CreateClientOptions<U, V>,
    ) -> Result<Self> {
        // if no Wallet is provided, a random one is created
        // let wallet = Arc::new(options.wallet.unwrap_or_else(|| {
        //     Wallet::new(AminoWallet::new(None, WalletOptions::default()).unwrap())
        // }));

        let wallet = Arc::new(options.wallet.expect("Wallet should be provided"));

        let enigma_utils = Arc::new(options.enigma_utils.expect("must provide enigma_utils"));

        // // if no EnigmaUtils is provided, one is created
        // let enigma_utils = options.enigma_utils.unwrap_or_else(|| {
        //     // if no seed is provided, one is randomly generated
        //     // TODO: query the chain for the enclave IO pubkey
        //     EnigmaUtils::new(options.encryption_seed, options.chain_id).unwrap()
        // });

        // let query_client_options = CreateQuerierOptions {
        //     url: options.url,
        //     chain_id: options.chain_id,
        //     enigma_utils: enigma_utils.clone(),
        // };
        let query = Querier::new(client.clone(), enigma_utils.clone());

        let tx_client_options = CreateTxSenderOptions {
            url: options.url,
            chain_id: options.chain_id,
            enigma_utils: enigma_utils.clone(),
            wallet: wallet.clone(),
            wallet_address: options.wallet_address.clone().unwrap_or_default().into(),
        };
        let tx = TxSender::new(client.clone(), tx_client_options);

        return Ok(Self {
            url: options.url.into(),
            query,
            tx,
            wallet,
            address: options.wallet_address.unwrap_or_default().into(),
            chain_id: options.chain_id.into(),
            enigma_utils,
        });
    }
}

impl<T, U, V> SecretNetworkClient<T, U, V>
where
    T: GrpcService<BoxBody> + Clone + Sync,
    T::Error: Into<StdError>,
    T::ResponseBody: Body<Data = Bytes> + Send + 'static,
    <T::ResponseBody as Body>::Error: Into<StdError> + Send,
    U: SecretUtils + Sync,
    V: Signer + Sync,
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
        let tx_response = self.decode_tx_response(tx_response, ibc_tx_options).await?;

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
    #[allow(deprecated)]
    pub async fn txs_query(
        &self,
        query: &str,
        ibc_tx_options: Option<IbcTxOptions>,
        pagination: Option<PageRequest>,
        order_by: OrderBy,
    ) -> Result<Option<Vec<TxResponse>>> {
        let events: Vec<String> = query.split(" AND ").map(|q| q.trim().to_string()).collect();
        debug!("events query: {events:?}");
        let order_by = order_by.into();

        let get_txs_event_request = GetTxsEventRequest {
            events,
            pagination,
            order_by,
            // I think these fields are not used in SDK v0.45
            page: 0,
            limit: 0,
            query: String::new(),
        };
        let get_txs_event_response = self.query.tx.get_txs_event(get_txs_event_request).await?;

        // TODO: work out pagination handling
        if let Some(pagination) = get_txs_event_response.pagination {
            debug!("not sure what to do about pagination yet");
        };

        let tx_responses = self
            .decode_tx_responses(get_txs_event_response.tx_responses, ibc_tx_options)
            .await?;

        Ok(Some(tx_responses))
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

    async fn decode_tx_responses(
        &self,
        tx_responses: Vec<TxResponseProto>,
        ibc_tx_options: Option<IbcTxOptions>,
    ) -> Result<Vec<TxResponse>> {
        // tx_responses
        //     .into_iter()
        //     .map(|tx_response| self.decode_tx_response(tx_response, ibc_tx_options.clone()))
        //     .collect()

        let mut decoded_responses = Vec::with_capacity(tx_responses.len());

        for tx_response in tx_responses {
            let decoded = self
                .decode_tx_response(tx_response, ibc_tx_options.clone())
                .await?;
            decoded_responses.push(decoded);
        }

        Ok(decoded_responses)
    }

    async fn decode_tx_response(
        &self,
        tx_response: TxResponseProto,
        ibc_tx_options: Option<IbcTxOptions>,
    ) -> Result<TxResponse> {
        let explicit_ibc_tx_options = ibc_tx_options.unwrap_or_default();
        let mut nonces = ComputeMsgToNonce::new();

        let Some(any) = tx_response.tx else {
            return Err("missing field: 'tx'".into());
        };

        debug!("processing tx...");
        // We process `tx` first to extract the nonces from the original Tx messages
        let mut tx: Tx = any.to_msg::<TxProto>()?.try_into()?;

        for (msg_index, any) in tx.body.messages.iter_mut().enumerate() {
            // Check if the message needs decryption
            match any.type_url.as_str() {
                "/secret.compute.v1beta1.MsgInstantiateContract" => {
                    debug!("found an encrypted message!");
                    let mut msg = any.to_msg::<MsgInstantiateContract>()?;
                    let mut nonce = [0u8; 32];
                    nonce.copy_from_slice(&msg.init_msg[0..32]);
                    let ciphertext = &msg.init_msg[64..];

                    if let Ok(plaintext) = self.enigma_utils.decrypt(&nonce, ciphertext).await {
                        // we only insert the nonce in the hashmap if we were able to use it!
                        nonces.insert(msg_index as u16, nonce);
                        msg.init_msg = serde_json::from_slice(&plaintext[64..])?;

                        *any = Any::from_msg::<MsgInstantiateContract>(&msg)?
                    }
                    debug!("unable to decrypt... oh well!");
                }
                "/secret.compute.v1beta1.MsgExecuteContract" => {
                    debug!("found an encrypted message!");
                    let mut msg = any.to_msg::<MsgExecuteContract>()?;
                    let mut nonce = [0u8; 32];
                    nonce.copy_from_slice(&msg.msg[0..32]);
                    let ciphertext = &msg.msg[64..];

                    if let Ok(plaintext) = self.enigma_utils.decrypt(&nonce, ciphertext).await {
                        nonces.insert(msg_index as u16, nonce);
                        msg.msg = serde_json::from_slice(&plaintext[64..])?;

                        *any = Any::from_msg::<MsgExecuteContract>(&msg)?
                    }
                    debug!("unable to decrypt... oh well!");
                }
                "/secret.compute.v1beta1.MsgMigrateContract" => {
                    debug!("found an encrypted message!");
                    let mut msg = any.to_msg::<MsgMigrateContract>()?;
                    let mut nonce = [0u8; 32];
                    nonce.copy_from_slice(&msg.msg[0..32]);
                    let ciphertext = &msg.msg[64..];

                    if let Ok(plaintext) = self.enigma_utils.decrypt(&nonce, ciphertext).await {
                        nonces.insert(msg_index as u16, nonce);
                        msg.msg = serde_json::from_slice(&plaintext[64..])?;

                        *any = Any::from_msg::<MsgMigrateContract>(&msg)?
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

        debug!("processing data...");
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
            // Check if the message needs decryption (has an associated nonce from earlier)
            if let Some(nonce) = nonces.get(&(msg_index as u16)) {
                match msg_data.msg_type.as_str() {
                    // if the message was a MsgInstantiateContract, then the data is in the form of
                    // MsgInstantiateContractResponse. same goes for Execute and Migrate.
                    "/secret.compute.v1beta1.MsgInstantiateContract" => {
                        debug!("found an encrypted message!");
                        let mut decoded =
                            <MsgInstantiateContractResponse as Message>::decode(&*msg_data.data)?;

                        if let Ok(bytes) = self.enigma_utils.decrypt(nonce, &decoded.data).await {
                            let msg_type =
                                "/secret.compute.v1beta1.MsgInstantiateContract".to_string();
                            let data = BASE64_STANDARD.decode(String::from_utf8(bytes)?)?;

                            *msg_data = MsgDataProto { msg_type, data }
                        }
                        debug!("unable to decrypt... oh well!");
                    }
                    "/secret.compute.v1beta1.MsgExecuteContract" => {
                        debug!("found an encrypted message!");
                        let mut decoded =
                            <MsgExecuteContractResponse as Message>::decode(&*msg_data.data)?;

                        if let Ok(bytes) = self.enigma_utils.decrypt(nonce, &decoded.data).await {
                            let msg_type = "/secret.compute.v1beta1.MsgExecuteContract".to_string();
                            let data = BASE64_STANDARD.decode(String::from_utf8(bytes)?)?;

                            *msg_data = MsgDataProto { msg_type, data }
                        }
                        debug!("unable to decrypt... oh well!");
                    }
                    "/secret.compute.v1beta1.MsgMigrateContract" => {
                        debug!("found an encrypted message!");
                        let mut decoded =
                            <MsgMigrateContractResponse as Message>::decode(&*msg_data.data)?;
                        if let Ok(bytes) = self.enigma_utils.decrypt(nonce, &decoded.data).await {
                            let msg_type = "/secret.compute.v1beta1.MsgMigrateContract".to_string();
                            let data = BASE64_STANDARD.decode(String::from_utf8(bytes)?)?;

                            *msg_data = MsgDataProto { msg_type, data }
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
        #[allow(deprecated)]
        let data = data
            .data
            .into_iter()
            .map(|item| MsgData::try_from(item).map_err(Error::from))
            .collect::<Result<Vec<MsgData>>>()?;

        // TODO: Process, decrypt the logs!
        let logs = tx_response.logs;

        let ibc_responses = None;

        debug!("processing events...");
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
            logs,
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
    async fn broadcast_tx(
        &self,
        tx_bytes: Vec<u8>,
        timeout_ms: u32,
        check_interval_ms: u32,
        mode: BroadcastMode,
        wait_for_commit: bool,
        ibc_tx_options: Option<IbcTxOptions>,
    ) -> Result<TxResponse> {
        todo!()
    }

    /// Prepare and sign an array of messages as a transaction.
    async fn sign_tx<M: Msg>(&self, messages: Vec<M>, tx_options: TxOptions) -> Result<Raw> {
        self.prepare_and_sign(messages, tx_options, false).await
    }

    /// Broadcast a signed transaction.
    async fn broadcast_signed_tx(
        &self,
        tx_bytes: Vec<u8>,
        tx_options: TxOptions,
    ) -> Result<TxResponse> {
        self.broadcast_tx(
            tx_bytes,
            tx_options.broadcast_timeout_ms,
            tx_options.broadcast_check_interval_ms,
            tx_options.broadcast_mode,
            tx_options.wait_for_commit,
            None,
        )
        .await
    }

    async fn prepare_and_sign<M: Msg>(
        &self,
        messages: Vec<M>,
        tx_options: TxOptions,
        simulate: bool,
    ) -> Result<Raw> {
        let gas_limit = tx_options.gas_limit;
        let gas_price_in_fee_denom = tx_options.gas_price_in_fee_denom;
        let fee_denom = tx_options.fee_denom;
        let memo = tx_options.memo;
        let fee_granter = tx_options.fee_granter;

        let explicit_signer_data = tx_options.explicit_signer_data;

        let tx_raw = self
            .sign(
                messages,
                StdFee {
                    gas: format!("{gas_limit}"),
                    amount: vec![Coin::new(
                        gas_to_fee(gas_limit, gas_price_in_fee_denom),
                        &fee_denom,
                    )?],
                    granter: fee_granter,
                },
                memo,
                explicit_signer_data,
                simulate,
            )
            .await?;

        Ok(Raw::from(tx_raw))
    }

    async fn sign_and_broadcast<M: Msg>(
        &self,
        messages: Vec<M>,
        tx_options: TxOptions,
    ) -> Result<TxResponse> {
        let tx_bytes = self
            .prepare_and_sign(messages, tx_options.clone(), false)
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

    async fn simulate<M: Msg>(
        &self,
        messages: Vec<M>,
        tx_options: TxOptions,
    ) -> Result<SimulateResponse> {
        let tx_bytes = self
            .prepare_and_sign(messages, tx_options.clone(), true)
            .await?
            .to_bytes()?;

        // TODO: figure out if this is deprecated in 0.45 or not
        #[allow(deprecated)]
        let request = SimulateRequest { tx: None, tx_bytes };
        let response = self.tx.simulate(request).await?;

        Ok(response)
    }

    /// Signs a transaction.
    ///
    /// Gets account number and sequence from the API, creates a sign doc, creates a single signature, and assembles the signed transaction.
    /// The sign mode (SIGN_MODE_DIRECT or SIGN_MODE_LEGACY_AMINO_JSON) is determined by this client's signer.
    ///
    /// You can pass signer data (account number, sequence and chain ID) explicitly instead of querying them
    /// from the chain. This is needed when signing for a multisig account, but it also allows for offline signing.
    async fn sign<M>(
        &self,
        messages: Vec<M>,
        fee: StdFee,
        memo: String,
        explicit_signer_data: Option<SignerData>,
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

pub fn gas_to_fee(gas_limit: u32, gas_price: f32) -> u128 {
    (gas_limit as f32 * gas_price).ceil() as u128
}

use secretrs::utils::encryption::SecretMsg;

#[async_trait(?Send)]
pub trait TxDecrypter {
    async fn encrypt<M: Serialize + Send + Sync>(
        &self,
        contract_code_hash: &str,
        msg: &M,
    ) -> Result<SecretMsg>;
    async fn decrypt(&self, nonce: &[u8; 32], ciphertext: &[u8]) -> Result<Vec<u8>>;
    async fn decrypt_tx_response<'a>(
        &'a self,
        tx: &'a mut TxResponse,
    ) -> Result<&'a mut TxResponse>;
}

#[async_trait]
pub trait TxDecoder {
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
        debug!("decoding tx_response...");
        let explicit_ibc_tx_options = ibc_tx_options.unwrap_or_default();

        let any = tx_response
            .tx
            .ok_or("'tx' field is required to decode_tx_response")?;
        let tx: Tx = any.to_msg::<TxProto>()?.try_into()?;

        let mut data =
            <TxMsgDataProto as Message>::decode(hex::decode(tx_response.data)?.as_ref())?;

        #[allow(deprecated)]
        let data = data
            .data
            .into_iter()
            .map(|item| MsgData::try_from(item).map_err(Error::from))
            .collect::<Result<Vec<MsgData>>>()?;

        let logs = tx_response.logs;

        // TODO:
        let ibc_responses = None;

        let events = tx_response
            .events
            .into_iter()
            .map(|event| Ok(event.try_into()?))
            .collect::<Result<Vec<Event>>>()?;

        Ok(TxResponse {
            height: tx_response.height as u64,
            txhash: tx_response.txhash.to_uppercase(),
            code: tx_response.code,
            codespace: tx_response.codespace,
            data,
            raw_log: tx_response.raw_log,
            logs,
            ibc_responses,
            info: tx_response.info,
            gas_wanted: tx_response.gas_wanted as u64,
            gas_used: tx_response.gas_used as u64,
            tx,
            timestamp: tx_response.timestamp,
            events,
        })
    }
}

#[async_trait]
pub trait TBD {
    async fn broadcast_tx(
        &self,
        tx_bytes: Vec<u8>,
        timeout_ms: u32,
        check_interval_ms: u32,
        mode: BroadcastMode,
        wait_for_commit: bool,
        ibc_tx_options: Option<IbcTxOptions>,
    ) -> Result<TxResponse> {
        // Default implementation
        todo!()
    }

    /// Prepare and sign an array of messages as a transaction.
    async fn sign_tx<M: Msg + Send>(&self, messages: Vec<M>, tx_options: TxOptions) -> Result<Raw> {
        self.prepare_and_sign(messages, tx_options, false).await
    }

    /// Broadcast a signed transaction.
    async fn broadcast_signed_tx(
        &self,
        tx_bytes: Vec<u8>,
        tx_options: TxOptions,
    ) -> Result<TxResponse> {
        self.broadcast_tx(
            tx_bytes,
            tx_options.broadcast_timeout_ms,
            tx_options.broadcast_check_interval_ms,
            tx_options.broadcast_mode,
            tx_options.wait_for_commit,
            None,
        )
        .await
    }

    async fn prepare_and_sign<M: Msg + Send>(
        &self,
        messages: Vec<M>,
        tx_options: TxOptions,
        simulate: bool,
    ) -> Result<Raw> {
        let gas_limit = tx_options.gas_limit;
        let gas_price_in_fee_denom = tx_options.gas_price_in_fee_denom;
        let fee_denom = tx_options.fee_denom;
        let memo = tx_options.memo;
        let fee_granter = tx_options.fee_granter;

        let explicit_signer_data = tx_options.explicit_signer_data;

        let tx_raw = self
            .sign(
                messages,
                StdFee {
                    gas: format!("{gas_limit}"),
                    amount: vec![Coin::new(
                        gas_to_fee(gas_limit, gas_price_in_fee_denom),
                        &fee_denom,
                    )?],
                    granter: fee_granter,
                },
                memo,
                explicit_signer_data,
                simulate,
            )
            .await?;

        Ok(Raw::from(tx_raw))
    }

    /// Signs a transaction.
    ///
    /// Gets account number and sequence from the API, creates a sign doc, creates a single signature, and assembles the signed transaction.
    /// The sign mode (SIGN_MODE_DIRECT or SIGN_MODE_LEGACY_AMINO_JSON) is determined by this client's signer.
    ///
    /// You can pass signer data (account number, sequence and chain ID) explicitly instead of querying them
    /// from the chain. This is needed when signing for a multisig account, but it also allows for offline signing.
    async fn sign<M: Msg + Send>(
        &self,
        messages: Vec<M>,
        fee: StdFee,
        memo: String,
        explicit_signer_data: Option<SignerData>,
        simulate: bool,
    ) -> Result<TxRaw> {
        todo!()
    }
}

use crate::tx::{ComputeServiceClient, TxServiceClient};

#[async_trait]
impl<T> TxDecoder for TxServiceClient<T>
where
    T: GrpcService<BoxBody> + Clone + Sync,
    T::Error: Into<StdError>,
    T::ResponseBody: Body<Data = Bytes> + Send + 'static,
    <T::ResponseBody as Body>::Error: Into<StdError> + Send,
{
}

#[async_trait]
impl<T, U, V> TxDecoder for ComputeServiceClient<T, U, V>
where
    T: GrpcService<BoxBody> + Clone + Sync,
    T::Error: Into<StdError>,
    T::ResponseBody: Body<Data = Bytes> + Send + 'static,
    <T::ResponseBody as Body>::Error: Into<StdError> + Send,
    U: SecretUtils + Sync,
    V: Signer + Sync,
{
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
