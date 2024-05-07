use super::{secret_network_client::SignDocCamelCase, Result};
use cosmrs::{
    crypto::{secp256k1::SigningKey, PublicKey},
    tx::SignDoc,
    Any, Coin,
};
use std::{fmt, str::FromStr};
use tonic::async_trait;

pub struct WalletOptions {
    pub hd_account_index: u32,
    pub coin_type: u32,
    pub bech32_prefix: String,
}

impl Default for WalletOptions {
    fn default() -> Self {
        Self {
            hd_account_index: 0,
            coin_type: 529,
            bech32_prefix: "secret".to_string(),
        }
    }
}

pub struct AminoWallet {
    /// The mnemonic phrase used to derive this account
    pub mnemonic: String,
    /// The account index in the HD derivation path
    pub hd_account_index: u32,
    /// The coin type in the HD derivation path
    pub coin_type: u32,
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
    pub fn from_seed(seed: [u8; 64], options: WalletOptions) -> Result<Self> {
        let path = "m/44'/529'/0'/0/0"
            .parse()
            .expect("invalid scrt derivation path");
        let prvk =
            bip32::XPrv::derive_from_path(seed, &path).expect("private key derivation failed");
        let pubk = SigningKey::from(&prvk).public_key();

        todo!()
    }

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
        let bech32_prefix = options.bech32_prefix;

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

    /// Get the accounts associated with this wallet
    pub fn get_accounts(&self) -> Vec<AccountData> {
        vec![AccountData {
            address: self.address.clone(),
            algo: Algo::Secp256k1,
            pubkey: self.public_key.to_bytes(),
        }]
    }

    /// Get the bech32 prefix
    pub fn bech32_prefix(&self) -> &str {
        &self.bech32_prefix
    }
}

#[derive(Debug)]
pub struct AminoMsg {
    pub r#type: String,
    pub value: Any,
}

/// Response after signing with Amino.
#[derive(Debug)]
pub struct AminoSignResponse {
    pub signed: StdSignDoc,
    pub signature: StdSignature,
}

/// Document to be signed.
#[derive(Debug)]
pub struct StdSignDoc {
    pub chain_id: String,
    pub account_number: String,
    pub sequence: String,
    pub fee: StdFee,
    pub msgs: Vec<AminoMsg>,
    pub memo: String,
}

/// Standard fee structure.
#[derive(Debug, Clone)]
pub struct StdFee {
    pub amount: Vec<Coin>,
    pub gas: String,
    pub granter: Option<String>,
}

/// Signature structure.
#[derive(Debug)]
pub struct StdSignature {
    pub pub_key: Pubkey,
    pub signature: String,
}

/// Public key type.
#[derive(Debug, Clone)]
pub struct Pubkey {
    pub key_type: String, // Flexible type, using String to avoid enum complexity.
    pub value: Vec<u8>,   // Most generic byte storage.
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
    pub address: String, // Assuming the address is a printable string.
    pub algo: Algo,
    pub pubkey: Vec<u8>, // Public key as a byte array.
}

/// SignDoc or SignDocCamelCase, assuming they are previously defined.
/// You could use an enum or separate structs if their structures differ significantly.
#[derive(Debug, Clone)]
pub enum SignDocVariant {
    SignDoc(SignDoc),
    SignDocCamelCase(SignDocCamelCase),
}

#[async_trait]
pub trait AminoSigner {
    async fn get_accounts() -> Result<Vec<AccountData>>;
    async fn sign_amino(signer_address: String, sign_doc: StdSignDoc) -> Result<AminoSignResponse>;
}
