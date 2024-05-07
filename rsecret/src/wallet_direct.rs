use cosmrs::{
    crypto::secp256k1,
    tendermint::chain::Id,
    tx::{AuthInfo, Body, SignDoc},
};

use sha2::{Digest, Sha256};

use super::wallet_amino::{AminoWallet, StdSignature};

#[derive(Debug)]
pub struct Wallet(AminoWallet);

impl Wallet {
    pub fn new(amino_wallet: AminoWallet) -> Self {
        Wallet(amino_wallet)
    }

    // async fn sign_direct(
    //     &self,
    //     address: String,
    //     sign_doc: SignDoc,
    // ) -> Result<DirectSignResponse, String> {
    //     if address != self.0.address {
    //         return Err(format!("Address {} not found in wallet", address));
    //     }
    //
    //     let message_hash = sha256(&sign_doc.into_bytes().unwrap());
    //     let signing_key = secp256k1::SigningKey::from_slice(&self.0.private_key).unwrap();
    //     let signature = signing_key.sign(&message_hash).unwrap();
    //     let signature = StdSignature {
    //         pub_key: &self.0.public_key,
    //         signature: signature.to_string(),
    //     };
    //
    //     Ok(DirectSignResponse {
    //         signed: sign_doc,
    //         signature,
    //     })
    // }
}

/// Response type for direct signing operations.
#[derive(Debug)]
pub struct DirectSignResponse {
    pub signed: SignDoc,
    pub signature: StdSignature,
}

fn sha256(data: &[u8]) -> Vec<u8> {
    // create a Sha256 object
    let mut hasher = Sha256::new();

    // write input message
    hasher.update(b"hello world");

    // read hash digest and consume hasher
    let result = hasher.finalize();
    result.to_vec()
}

async fn serialize_sign_doc(
    auth_info: &AuthInfo,
    body: &Body,
    chain_id: &Id,
    account_number: u64,
) -> Result<Vec<u8>, cosmrs::ErrorReport> {
    SignDoc::new(body, auth_info, chain_id, account_number).and_then(SignDoc::into_bytes)
}
