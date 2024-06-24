use super::wallet_amino::{
    encode_secp256k1_signature, serialize_std_sign_doc, AccountData, Algo, AminoSignResponse,
    AminoSigner, AminoWallet, StdSignDoc, StdSignature,
};
use crate::{secret_network_client::SignDocCamelCase, Error::InvalidSigner, Result};
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
}

#[derive(Debug, Clone)]
pub enum SignDocVariant {
    SignDoc(SignDoc),
    SignDocCamelCase(SignDocCamelCase),
}

// Alternate approach:
// impl SignDocVariant {
//     pub fn into_bytes(self) -> Result<Vec<u8>> {
//         match self {
//             SignDocVariant::SignDoc(doc) => Ok(doc.into_bytes()?),
//             SignDocVariant::SignDocCamelCase(doc) => Ok(SignDoc::try_from(doc)?.into_bytes()?),
//         }
//     }
// }

/// Response type for direct signing operations.
#[derive(Debug)]
pub struct DirectSignResponse {
    /// The sign doc that was signed.
    /// This may be different from the input SignDoc when the signer modifies it as part of the signing process.
    pub signed: SignDocVariant,
    pub signature: StdSignature,
}

#[async_trait]
pub trait DirectSigner {
    /// Get AccountData array from wallet. Rejects if not enabled.
    async fn get_accounts(&self) -> Result<Vec<AccountData>>;

    /// Get [SignMode] for signing a tx.
    async fn get_sign_mode(&self) -> Result<SignMode> {
        Ok(SignMode::Direct)
    }

    /// Request signature from whichever key corresponds to provided bech32-encoded address. Rejects if not enabled.
    ///
    /// The signer implementation may offer the user the ability to override parts of the sign_doc. It must
    /// return the doc that was signed in the response.
    async fn sign_amino(
        &self,
        signer_address: &str,
        sign_doc: StdSignDoc,
    ) -> Result<AminoSignResponse>;

    async fn sign_permit(
        &self,
        signer_address: &str,
        sign_doc: StdSignDoc,
    ) -> Result<AminoSignResponse>;

    async fn sign_direct(
        &self,
        signer_address: &str,
        sign_doc: SignDocVariant,
    ) -> Result<DirectSignResponse>;
}

#[async_trait]
impl DirectSigner for Wallet {
    async fn get_accounts(&self) -> Result<Vec<AccountData>> {
        Ok(vec![AccountData {
            address: self.0.address.clone(),
            algo: Algo::Secp256k1,
            pubkey: self.0.public_key.to_bytes(),
        }])
    }

    /// Signs a [StdSignDoc] using Amino encoding.
    async fn sign_amino(
        &self,
        signer_address: &str,
        sign_doc: StdSignDoc,
    ) -> Result<AminoSignResponse> {
        if signer_address != self.0.address {
            return Err(InvalidSigner {
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

    async fn sign_permit(
        &self,
        signer_address: &str,
        sign_doc: StdSignDoc,
    ) -> Result<AminoSignResponse> {
        todo!()
    }

    async fn sign_direct(
        &self,
        signer_address: &str,
        sign_doc: SignDocVariant,
    ) -> Result<DirectSignResponse> {
        if signer_address != self.0.address {
            return Err(InvalidSigner {
                signer_address: signer_address.to_string(),
            });
        }

        let message_hash = Sha256::digest(serialize_sign_doc(sign_doc.clone())?);

        let signature = self.0.private_key.sign(&message_hash)?;

        Ok(DirectSignResponse {
            signed: sign_doc,
            signature: encode_secp256k1_signature(
                &self.0.public_key.to_bytes(),
                &signature.to_bytes(),
            )?,
        })
    }
}

#[inline]
fn serialize_sign_doc(sign_doc: SignDocVariant) -> Result<Vec<u8>> {
    // sign_doc.into_bytes()
    match sign_doc {
        SignDocVariant::SignDoc(sign_doc) => Ok(sign_doc.into_bytes()?),
        SignDocVariant::SignDocCamelCase(sign_doc) => Ok(sign_doc.into_bytes()?),
    }
}
