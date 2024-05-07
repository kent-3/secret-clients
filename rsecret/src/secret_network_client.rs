#![allow(unused)]

use crate::{
    query::Querier,
    tx::TxSender,
    wallet_amino::{AccountData, Algo, AminoSignResponse, AminoSigner, AminoWallet, StdSignDoc},
    wallet_direct::Wallet,
    Error, Result,
};
use async_trait::async_trait;
use secretrs::{
    proto::{
        cosmos::tx::v1beta1::{
            AuthInfo, BroadcastMode, SignDoc, SignerInfo, Tx as TxPb, TxBody, TxRaw,
        },
        tendermint::abci::Event,
    },
    EncryptionUtils,
};
use std::{str::FromStr, sync::Arc, time::Duration};
use tonic::codegen::{Body, Bytes, StdError};

/// Options to configure the creation of a client.
#[derive(Debug)]
pub struct CreateClientOptions {
    /// A URL to the API service, also known as LCD, REST API or gRPC-gateway, typically on port 1317.
    pub url: &'static str,
    /// The chain-id used in encryption code & when signing transactions.
    pub chain_id: &'static str,
    /// An optional wallet for signing transactions & permits. If `wallet` is supplied,
    /// `wallet_address` & `chain_id` must also be supplied.
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

#[derive(Debug, Clone)]
pub struct TxResponse {
    /// Block height in which the tx was committed on-chain
    pub height: u64,
    /// An RFC 3339 timestamp of when the tx was committed on-chain.
    /// The format is `{year}-{month}-{day}T{hour}:{min}:{sec}[.{frac_sec}]Z`.
    pub timestamp: String,
    /// Transaction hash (might be used as transaction ID). Guaranteed to be non-empty upper-case hex
    pub transaction_hash: String,
    /// Transaction execution error code. 0 on success.
    pub code: u32,
    /// Namespace for the Code
    pub codespace: String,
    /// Additional information. May be non-deterministic.
    pub info: String,
    /// If code != 0, rawLog contains the error.
    /// If code = 0 you'll probably want to use `jsonLog` or `arrayLog`.
    /// Values are not decrypted.
    pub raw_log: String,
    /// If code = 0, `jsonLog = serde_json::from_str(raw_log)`. Values are decrypted if possible.
    pub json_log: Option<JsonLog>,
    /// If code = 0, `array_log` is a flattened `json_log`. Values are decrypted if possible.
    pub array_log: Option<ArrayLog>,
    /// Events defines all the events emitted by processing a transaction. Note,
    /// these events include those emitted by processing all the messages and those
    /// emitted from the ante handler. Whereas Logs contains the events, with
    /// additional metadata, emitted only by processing the messages.
    ///
    /// Note: events are not decrypted.
    pub events: Vec<Event>,
    /// Return value (if there's any) for each input message
    pub data: Vec<Vec<u8>>,
    /// Decoded transaction input.
    pub tx: TxPb,
    /// Amount of gas that was actually used by the transaction.
    pub gas_used: u64,
    /// Gas limit that was originally set by the transaction.
    pub gas_wanted: u64,
    /// If code = 0 and the tx resulted in sending IBC packets, `ibc_ack_txs` is a list of IBC acknowledgement or timeout transactions which signal whether the original IBC packet was accepted, rejected, or timed-out on the receiving chain.
    pub ibc_responses: Vec<IbcResponse>,
}

#[derive(Debug, Clone)]
pub struct JsonLogEntry {
    pub msg_index: u32,
    pub events: Vec<Event>,
}

#[derive(Debug, Clone)]
pub struct JsonLog(pub Vec<JsonLogEntry>);

#[derive(Debug, Clone)]
pub struct ArrayLogEntry {
    pub msg: u32,
    pub r#type: String,
    pub key: String,
    pub value: String,
}

#[derive(Debug, Clone)]
pub struct ArrayLog(pub Vec<ArrayLogEntry>);

#[derive(Debug, Clone)]
pub enum IbcResponseType {
    Ack,
    Timeout,
}

#[derive(Debug, Clone)]
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
    pub wallet: Option<Wallet>, // TODO
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
            encryption_utils, // tx_options,
        })
    }

    // I think it'd be a nice feature to be able to change the default tx options
    // pub fn tx_options(&mut self, options: TxOptions) -> &mut Self {
    //     self.tx_options = Arc::new(options);
    //     self
    // }
}

/// A signer capable of signing transactions.
/// Placeholder for actual implementation details.
pub trait Signer {
    // Define methods relevant to the Signer trait here
    fn sign();
}

/// Placeholder for actual implementation details.
pub trait DirectSigner: Signer {
    fn sign_direct();
}

impl Signer for Wallet {
    fn sign() {
        todo!()
    }
}

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
