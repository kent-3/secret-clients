use super::wallet_amino::{
    encode_secp256k1_signature, AccountData, Algo, AminoWallet, StdSignature,
};
use crate::{Error::InvalidSigner, Result};
use secretrs::tx::SignDoc;
use sha2::{Digest, Sha256};

/**
Wallet is a wallet capable of signing on transactions.

 `Wallet` can just extend `AminoWallet` and be a valid `DirectSigner` because
 `SecretNetworkClient` checks first for the existence of `signDirect` function
 before checking for `signAmino` function.
*/
#[derive(Debug)]
pub struct Wallet(AminoWallet);

impl Wallet {
    pub fn new(amino_wallet: AminoWallet) -> Self {
        Wallet(amino_wallet)
    }

    async fn get_accounts(&self) -> Vec<AccountData> {
        vec![AccountData {
            address: self.0.address.clone(),
            algo: Algo::Secp256k1,
            pubkey: self.0.public_key.to_bytes(),
        }]
    }

    async fn sign_direct(
        &self,
        signer_address: &str,
        sign_doc: SignDoc,
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

fn serialize_sign_doc(sign_doc: SignDoc) -> Result<Vec<u8>> {
    sign_doc.into_bytes().map_err(Into::into)
    // match sign_doc {
    //     SignDocVariant::SignDoc(sign_doc) => Ok(sign_doc.into_bytes()?),
    //     SignDocVariant::SignDocCamelCase(sign_doc) => Err("signDocCamelCase not allowed".into()),
    // }
}

/// Response type for direct signing operations.
#[derive(Debug)]
pub struct DirectSignResponse {
    pub signed: SignDoc,
    pub signature: StdSignature,
}
