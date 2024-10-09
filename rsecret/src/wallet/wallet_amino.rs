use super::Error;
use crate::wallet::{DirectSignResponse, Signer};
pub type Result<T, E = super::Error> = core::result::Result<T, E>;
use async_trait::async_trait;
use base64::prelude::{Engine, BASE64_STANDARD};
use secretrs::{
    crypto::{secp256k1::SigningKey, PublicKey},
    tx::{SignDoc, SignMode},
    Coin,
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::{fmt, str::FromStr};

const SECRET_COIN_TYPE: u16 = 529;
const SECRET_BECH32_PREFIX: &str = "secret";

/// Available options when creating a Wallet.
#[derive(Debug)]
pub struct WalletOptions {
    /// The account index in the HD derivation path. Defaults to `0`.
    pub hd_account_index: u32,
    /// The coin type in the HD derivation path. Defaults to Secret's `529`.
    pub coin_type: u16,
    /// The bech32 prefix for the account's address. Defaults to `"secret"`
    pub bech32_prefix: &'static str,
}

impl Default for WalletOptions {
    fn default() -> Self {
        Self {
            hd_account_index: 0,
            coin_type: SECRET_COIN_TYPE,
            bech32_prefix: SECRET_BECH32_PREFIX,
        }
    }
}

/// A wallet capable of signing on the legacy Amino encoding.
///
/// Amino encoding is still a must-use when signing with Ledger and thus still
/// supported in the chain, but is phased out slowly.
///
/// In secret.js, AminoWallet is mainly used for testing and should not be used
/// for anything else. The reason is that some Msg types don't support Amino
/// encoding anymore and thus won't work with this wallet (and Ledger).
/// Msgs that do support Amino encoding also must encode with Protobuf,
/// so if a Msg is working as intended with AminoWallet, it'll also work with [`Wallet`].
///
/// For reference, even txs that are signed using Amino, are sent to the chain
/// using Protobuf encoding, so inside the chain the tx is converted to Amino
/// in order to verify the signature.
///
/// [`Wallet`]: crate::wallet_proto::Wallet
pub struct AminoWallet {
    /// The mnemonic phrase used to derive this account
    mnemonic: String,
    /// The account index in the HD derivation path
    pub hd_account_index: u32,
    /// The coin type in the HD derivation path
    pub coin_type: u16,
    /// The secp256k1 private key that was derived from `mnemonic` + `hdAccountIndex`
    pub(super) private_key: SigningKey,
    /// The secp256k1 public key that was derived from `private_key`
    pub public_key: PublicKey,
    /// The account's secret address, derived from `public_key`
    pub address: String,
    /// The bech32 prefix for the account's address
    bech32_prefix: String,
}

impl fmt::Debug for AminoWallet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Wallet")
            .field("mnemonic", &self.mnemonic)
            .field("hd_account_index", &self.hd_account_index)
            .field("coin_type", &self.coin_type)
            .field("privkey", &"[REDACTED]")
            .field("public_key", &self.public_key)
            .field("address", &self.address)
            .field("bech32_prefix", &self.bech32_prefix)
            .finish()
    }
}

impl AminoWallet {
    /// Import mnemonic or generate random if `None`.
    ///
    /// See [`WalletOptions`].
    pub fn new(mnemonic: Option<String>, options: WalletOptions) -> Result<Self> {
        // Generate a new mnemonic if not provided
        let mnemonic = if let Some(mnemonic) = mnemonic {
            bip39::Mnemonic::from_str(&mnemonic)
        } else {
            use nanorand::rand::Rng;
            let mut seed = [0u8; 32];
            let mut rng = nanorand::rand::ChaCha8::new();
            rng.fill_bytes(&mut seed);
            bip39::Mnemonic::from_entropy(&seed)
        }?;

        let hd_account_index = options.hd_account_index;
        let coin_type = options.coin_type;
        let bech32_prefix = options.bech32_prefix.to_string();

        let seed = mnemonic.to_seed("");
        let path = format!("m/44'/{coin_type}'/0'/0/{hd_account_index}")
            .parse()
            .expect("invalid scrt derivation path");
        let secret_hd = secretrs::bip32::XPrv::derive_from_path(seed, &path)
            .expect("private key derivation failed");

        let private_key = SigningKey::from(&secret_hd);
        let public_key = private_key.public_key();

        let address = public_key.account_id("secret")?.to_string();

        Ok(Self {
            mnemonic: mnemonic.to_string(),
            hd_account_index,
            coin_type,
            private_key,
            public_key,
            address,
            bech32_prefix,
        })
    }

    /// Get the bech32 prefix
    pub fn bech32_prefix(&self) -> &str {
        &self.bech32_prefix
    }
}

#[async_trait]
impl Signer for AminoWallet {
    /// Get the accounts associated with this wallet.
    async fn get_accounts(&self) -> Result<Vec<AccountData>, super::Error> {
        Ok(vec![AccountData {
            address: self.address.clone(),
            algo: Algo::Secp256k1,
            pubkey: self.public_key.to_bytes(),
        }])
    }

    async fn get_sign_mode(&self) -> std::result::Result<SignMode, super::Error> {
        Ok(SignMode::LegacyAminoJson)
    }

    /// Signs a [StdSignDoc] using Amino encoding.
    async fn sign_amino<T: Serialize + Send + Sync>(
        &self,
        signer_address: &str,
        sign_doc: StdSignDoc<T>,
    ) -> Result<AminoSignResponse<T>, super::Error> {
        if signer_address != self.address {
            return Err(Error::SignerError {
                signer_address: signer_address.to_string(),
            });
        }

        let message_hash = Sha256::digest(serialize_std_sign_doc(&sign_doc));

        let signature = self.private_key.sign(&message_hash)?;

        Ok(AminoSignResponse {
            signed: sign_doc,
            signature: encode_secp256k1_signature(
                &self.public_key.to_bytes(),
                &signature.to_bytes(),
            )?,
        })
    }

    async fn sign_permit<T: Serialize + Send + Sync>(
        &self,
        signer_address: &str,
        sign_doc: StdSignDoc<T>,
    ) -> Result<AminoSignResponse<T>, super::Error> {
        todo!()
    }

    async fn sign_direct(
        &self,
        signer_address: &str,
        sign_doc: SignDoc,
    ) -> std::result::Result<DirectSignResponse, super::Error> {
        unimplemented!("This is an Amino Wallet")
    }
}

/// Encodes a secp256k1 signature object.
pub(crate) fn encode_secp256k1_signature(
    pubkey: &[u8],
    signature: &[u8],
) -> Result<StdSignature, super::Error> {
    if signature.len() != 64 {
        return Err(Error::SignatureError(
            "Signature must be 64 bytes long".into(),
        ));
    }

    Ok(StdSignature {
        pub_key: encode_secp256k1_pubkey(pubkey)?,
        signature: BASE64_STANDARD.encode(signature),
    })
}

/// Encodes a secp256k1 public key.
fn encode_secp256k1_pubkey(pubkey: &[u8]) -> Result<Pubkey, super::Error> {
    if pubkey.len() != 33 || (pubkey[0] != 0x02 && pubkey[0] != 0x03) {
        return Err(
            "Public key must be compressed secp256k1, i.e. 33 bytes starting with 0x02 or 0x03"
                .into(),
        );
    }

    Ok(Pubkey {
        r#type: "tendermint/PubKeySecp256k1".to_string(),
        value: BASE64_STANDARD.encode(pubkey),
    })
}

/// An Amino encoded message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AminoMsg<T: Serialize> {
    pub r#type: String,
    pub value: T,
}

/// Response after signing with Amino.
#[derive(Debug, Serialize, Deserialize)]
pub struct AminoSignResponse<T: Serialize> {
    /// The sign_doc that was signed.
    ///
    /// This may be different from the input sign_doc when the signer modifies it as part of the signing process.
    pub signed: StdSignDoc<T>,
    pub signature: StdSignature,
}

/// The document to be signed.
///
/// See https://docs.cosmos.network/master/modules/auth/03_types.html#stdsigndoc
#[derive(Debug, Serialize, Deserialize)]
pub struct StdSignDoc<T: Serialize> {
    pub chain_id: String,
    pub account_number: String,
    pub sequence: String,
    pub fee: StdFee,
    pub msgs: Vec<AminoMsg<T>>,
    pub memo: String,
}

/// Standard fee.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StdFee {
    #[serde(
        serialize_with = "serialize_coins",
        deserialize_with = "deserialize_coins"
    )]
    pub amount: Vec<Coin>,
    pub gas: String,
    pub granter: Option<String>,
}

// TODO: name better
/// A helper struct for serialization/deserialization of Coin where amount is a string
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct CoinSerializable {
    denom: secretrs::Denom,
    amount: String, // Serialize amount as a string
}

impl From<secretrs::Coin> for CoinSerializable {
    fn from(coin: secretrs::Coin) -> Self {
        CoinSerializable {
            denom: coin.denom,
            amount: coin.amount.to_string(),
        }
    }
}

// Custom serializer for Vec<Coin> where only `amount` is serialized as a string
fn serialize_coins<S>(coins: &Vec<Coin>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    let coins_as_serializable: Vec<_> = coins
        .iter()
        .map(|coin| {
            CoinSerializable {
                denom: coin.denom.clone(),
                amount: coin.amount.to_string(), // Serialize `u128` as string
            }
        })
        .collect();

    coins_as_serializable.serialize(serializer)
}

// Custom deserializer for Vec<Coin> where only `amount` is deserialized from a string
fn deserialize_coins<'de, D>(deserializer: D) -> Result<Vec<Coin>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let coins_as_serializable: Vec<CoinSerializable> = Vec::deserialize(deserializer)?;
    let coins: Result<Vec<Coin>, D::Error> = coins_as_serializable
        .into_iter()
        .map(|coin_serializable| {
            let amount =
                u128::from_str(&coin_serializable.amount).map_err(serde::de::Error::custom)?;
            Ok(Coin {
                denom: coin_serializable.denom,
                amount,
            })
        })
        .collect();
    coins
}

/// Standard signature.
#[derive(Debug, Serialize, Deserialize)]
pub struct StdSignature {
    #[serde(rename = "pubKey", alias = "pub_key")]
    pub pub_key: Pubkey,
    pub signature: String,
}

// TODO: use this enum instead of Strings

/// Enum for allowed public key types.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PubkeyType {
    #[serde(rename = "tendermint/PubKeySecp256k1")]
    PubKeySecp256k1,
    #[serde(rename = "tendermint/PubKeyEd25519")]
    PubKeyEd25519,
    #[serde(rename = "tendermint/PubKeySr25519")]
    PubKeySr25519,
}

/// Public key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Pubkey {
    /// Possible types include:
    /// - "tendermint/PubKeySecp256k1"
    /// - "tendermint/PubKeyEd25519"
    /// - "tendermint/PubKeySr25519
    pub r#type: String,
    /// Base64 encoded String
    pub value: String,
}

/// Algorithm types used for signing.
#[allow(unused)]
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Algo {
    Secp256k1,
    Ed25519,
    Sr25519,
}

/// Data related to an account.
#[derive(Clone, Serialize, Deserialize)]
pub struct AccountData {
    pub address: String,
    pub algo: Algo,
    pub pubkey: Vec<u8>,
}

impl std::fmt::Debug for AccountData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Account")
            .field("address", &self.address)
            .field("algo", &self.algo)
            .field("pubkey", &BASE64_STANDARD.encode(&self.pubkey)) // Convert pubkey to base64
            .finish()
    }
}

/// Sorts a JSON object by its keys recursively.
pub(crate) fn sort_object(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut sorted_map = Map::new();
            for (key, val) in map {
                sorted_map.insert(key.clone(), sort_object(val));
            }
            Value::Object(sorted_map)
        }
        Value::Array(vec) => Value::Array(vec.iter().map(sort_object).collect()),
        _ => value.clone(),
    }
}

/// Returns a JSON string with objects sorted by key, used for Amino signing.
fn json_sorted_stringify(value: &Value) -> String {
    serde_json::to_string(&sort_object(value)).unwrap()
}

/// Serializes a `StdSignDoc` object to a sorted and UTF-8 encoded JSON string
pub(crate) fn serialize_std_sign_doc<T: Serialize>(sign_doc: &StdSignDoc<T>) -> Vec<u8> {
    let value = serde_json::to_value(sign_doc).unwrap();
    json_sorted_stringify(&value).as_bytes().to_vec()
}
