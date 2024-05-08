use super::{secret_network_client::SignDocCamelCase, Error, Result};
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

pub const SECRET_COIN_TYPE: u16 = 529;
pub const SECRET_BECH32_PREFIX: &'static str = "secret";

pub struct WalletOptions {
    pub hd_account_index: u32,
    pub coin_type: u16,
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

pub struct AminoWallet {
    /// The mnemonic phrase used to derive this account
    pub mnemonic: String,
    /// The account index in the HD derivation path
    pub hd_account_index: u32,
    /// The coin type in the HD derivation path
    pub coin_type: u16,
    /// The secp256k1 private key that was derived from `mnemonic` + `hdAccountIndex`
    pub private_key: SigningKey,
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
    pub fn new(mnemonic: Option<String>, options: WalletOptions) -> Result<Self> {
        // Generate a new mnemonic if not provided
        let mnemonic = if let Some(mnemonic) = mnemonic {
            bip39::Mnemonic::from_str(&mnemonic)
        } else {
            use nanorand::rand::Rng;
            let mut seed = [0; 64];
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
        let secret_hd =
            bip32::XPrv::derive_from_path(seed, &path).expect("private key derivation failed");

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
impl AminoSigner for AminoWallet {
    /// Get the accounts associated with this wallet
    async fn get_accounts(&self) -> Vec<AccountData> {
        vec![AccountData {
            address: self.address.clone(),
            algo: Algo::Secp256k1,
            pubkey: self.public_key.to_bytes(),
        }]
    }

    async fn sign_amino(
        &self,
        signer_address: String,
        sign_doc: StdSignDoc,
    ) -> Result<AminoSignResponse> {
        if signer_address != self.address {
            return Err(format!("Address {signer_address} not found in wallet").into());
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
}

/// Encodes a secp256k1 signature object
pub(crate) fn encode_secp256k1_signature(pubkey: &[u8], signature: &[u8]) -> Result<StdSignature> {
    if signature.len() != 64 {
        return Err("Signature must be 64 bytes long".into());
    }

    Ok(StdSignature {
        pub_key: encode_secp256k1_pubkey(pubkey)?,
        signature: BASE64_STANDARD.encode(&signature),
    })
}

/// Encodes a secp256k1 public key
fn encode_secp256k1_pubkey(pubkey: &[u8]) -> Result<Pubkey> {
    if pubkey.len() != 33 || (pubkey[0] != 0x02 && pubkey[0] != 0x03) {
        return Err(
            "Public key must be compressed secp256k1, i.e. 33 bytes starting with 0x02 or 0x03"
                .into(),
        );
    }

    Ok(Pubkey {
        r#type: "tendermint/PubKeySecp256k1".to_string(),
        value: BASE64_STANDARD.encode(&pubkey).into(),
    })
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AminoMsg {
    pub r#type: String,
    pub value: Vec<u8>,
}

/// Response after signing with Amino.
#[derive(Debug)]
pub struct AminoSignResponse {
    pub signed: StdSignDoc,
    pub signature: StdSignature,
}

/// Document to be signed.
#[derive(Debug, Serialize, Deserialize)]
pub struct StdSignDoc {
    pub chain_id: String,
    pub account_number: String,
    pub sequence: String,
    pub fee: StdFee,
    pub msgs: Vec<AminoMsg>,
    pub memo: String,
}

/// Standard fee.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StdFee {
    pub amount: Vec<Coin>,
    pub gas: String,
    pub granter: Option<String>,
}

/// Standard signature.
#[allow(non_snake_case)]
#[derive(Debug)]
pub struct StdSignature {
    pub pub_key: Pubkey,
    // pub pubKey: Pubkey, TODO:
    pub signature: String,
}

/// Public key type.
#[derive(Debug, Clone)]
pub struct Pubkey {
    pub r#type: String, // Flexible type, using String to avoid enum complexity.
    pub value: Vec<u8>,
}

/// Algorithm types used for signing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algo {
    Secp256k1,
    Ed25519,
    Sr25519,
}

/// Data related to an account.
#[derive(Debug, Clone)]
pub struct AccountData {
    pub address: String,
    pub algo: Algo,
    pub pubkey: Vec<u8>,
}

/// Sorts a JSON object by its keys recursively
pub fn sort_object(value: &Value) -> Value {
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
pub fn serialize_std_sign_doc(sign_doc: &StdSignDoc) -> Vec<u8> {
    let value = serde_json::to_value(sign_doc).unwrap();
    json_sorted_stringify(&value).as_bytes().to_vec()
}

#[derive(Debug, Clone)]
pub enum SignDocVariant {
    SignDoc(SignDoc),
    SignDocCamelCase(SignDocCamelCase),
}

/// Response after signing with Amino.
#[derive(Debug)]
pub struct DirectSignResponse {
    /// The sign doc that was signed.
    /// This may be different from the input SignDoc when the signer modifies it as part of the signing process.
    pub signed: SignDocVariant,
    pub signature: StdSignature,
}

#[async_trait]
pub trait DirectSigner {
    async fn get_accounts(&self) -> Vec<AccountData>;
    async fn sign_direct(
        &self,
        signer_address: &str,
        sign_doc: SignDocVariant,
    ) -> Result<DirectSignResponse>;
}

#[async_trait]
pub trait AminoSigner {
    async fn get_accounts(&self) -> Vec<AccountData>;
    async fn get_sign_mode(&self) -> Result<SignMode> {
        unimplemented!()
    }
    async fn sign_amino(
        &self,
        signer_address: String,
        sign_doc: StdSignDoc,
    ) -> Result<AminoSignResponse>;
    async fn sign_permit(
        &self,
        signer_address: &str,
        sign_doc: &StdSignDoc,
    ) -> Result<AminoSignResponse> {
        unimplemented!()
    }
}

enum Signer {
    Amino(Box<dyn AminoSigner + Sync>),
    Direct(Box<dyn DirectSigner + Sync>),
}
