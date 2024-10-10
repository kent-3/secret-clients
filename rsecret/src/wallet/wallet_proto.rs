use super::{
    wallet_amino::{
        encode_secp256k1_signature, serialize_std_sign_doc, AccountData, Algo, AminoSignResponse,
        AminoWallet, StdSignDoc, StdSignature,
    },
    Error, Signer,
};

pub type Result<T, E = super::Error> = core::result::Result<T, E>;

use async_trait::async_trait;
use base64::prelude::{Engine, BASE64_STANDARD};
use secretrs::{
    crypto::{secp256k1::SigningKey, PublicKey},
    tx::SignMode,
    Coin,
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::{fmt, str::FromStr};

/// Wallet is a wallet capable of signing on transactions.
///
/// `Wallet` can just extend `AminoWallet` and be a valid `DirectSigner` because
/// `SecretNetworkClient` checks first for the existence of `signDirect` function
/// before checking for `signAmino` function.
#[derive(Debug)]
pub struct Wallet(AminoWallet);

impl Wallet {
    pub fn new(amino_wallet: AminoWallet) -> Self {
        Wallet(amino_wallet)
    }

    /// Get [SignMode] for signing a tx.
    pub async fn get_sign_mode(&self) -> Result<SignMode> {
        Ok(SignMode::Direct)
    }
}

/// Local SignDoc type to be able to serialize to JavaScript. We lose the methods into_proto() and
/// into_bytes(), but are able to use serde_wasm_bindgen::{to_value, from_value}.
#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct SignDoc {
    pub body_bytes: Vec<u8>,
    pub auth_info_bytes: Vec<u8>,
    pub chain_id: String,
    pub account_number: u64,
}

impl std::fmt::Debug for SignDoc {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignDoc")
            .field("body_bytes", &BASE64_STANDARD.encode(&self.body_bytes))
            .field(
                "auth_info_bytes",
                &BASE64_STANDARD.encode(&self.auth_info_bytes),
            )
            .field("chain_id", &self.chain_id)
            .field("account_number", &self.account_number)
            .finish()
    }
}

impl From<secretrs::tx::SignDoc> for SignDoc {
    fn from(sign_doc: secretrs::tx::SignDoc) -> Self {
        Self {
            body_bytes: sign_doc.body_bytes,
            auth_info_bytes: sign_doc.auth_info_bytes,
            chain_id: sign_doc.chain_id,
            account_number: sign_doc.account_number,
        }
    }
}

impl From<SignDoc> for secretrs::tx::SignDoc {
    fn from(sign_doc: SignDoc) -> Self {
        Self {
            body_bytes: sign_doc.body_bytes,
            auth_info_bytes: sign_doc.auth_info_bytes,
            chain_id: sign_doc.chain_id,
            account_number: sign_doc.account_number,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct SignedSignDoc {
    pub body_bytes: Vec<u8>,
    pub auth_info_bytes: Vec<u8>,
    pub chain_id: String,
    pub account_number: AccountNumber,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AccountNumber {
    pub low: u32,
    pub high: u32,
    pub unsigned: bool,
}

/// Response type for direct signing operations.
#[derive(Debug, Serialize, Deserialize)]
pub struct DirectSignResponse {
    /// The sign doc that was signed.
    /// This may be different from the input SignDoc when the signer modifies it as part of the signing process.
    pub signed: SignedSignDoc,
    pub signature: StdSignature,
}

#[async_trait]
impl Signer for Wallet {
    // type Error = crate::Error;

    async fn get_accounts(&self) -> Result<Vec<AccountData>, super::Error> {
        Ok(vec![AccountData {
            address: self.0.address.clone(),
            algo: Algo::Secp256k1,
            pubkey: self.0.public_key.to_bytes(),
        }])
    }

    async fn get_sign_mode(&self) -> std::result::Result<SignMode, super::Error> {
        Ok(SignMode::Direct)
    }

    /// Signs a [StdSignDoc] using Amino encoding.
    async fn sign_amino<T: Serialize + Send + Sync>(
        &self,
        signer_address: &str,
        sign_doc: StdSignDoc<T>,
    ) -> Result<AminoSignResponse<T>, super::Error> {
        if signer_address != self.0.address {
            return Err(Error::SignerError {
                signer_address: signer_address.to_string(),
            });
        }

        let message_hash = Sha256::digest(serialize_std_sign_doc(&sign_doc));

        let signature = self.0.private_key.sign(&message_hash)?;

        Ok(AminoSignResponse {
            signed: sign_doc,
            signature: encode_secp256k1_signature(
                &self.0.public_key.to_bytes(),
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
        sign_doc: secretrs::tx::SignDoc,
    ) -> Result<DirectSignResponse, super::Error> {
        if signer_address != self.0.address {
            return Err(Error::SignerError {
                signer_address: signer_address.to_string(),
            });
        }

        let message_hash = Sha256::digest(sign_doc.clone().into_bytes()?);

        let signature = self.0.private_key.sign(&message_hash)?;

        let signed = SignedSignDoc {
            body_bytes: sign_doc.body_bytes,
            auth_info_bytes: sign_doc.auth_info_bytes,
            chain_id: sign_doc.chain_id,
            account_number: AccountNumber {
                low: sign_doc.account_number as u32,
                high: 0,
                unsigned: false,
            },
        };

        Ok(DirectSignResponse {
            signed,
            signature: encode_secp256k1_signature(
                &self.0.public_key.to_bytes(),
                &signature.to_bytes(),
            )?,
        })
    }
}
