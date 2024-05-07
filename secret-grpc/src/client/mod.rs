use crate::query::auth::AuthQuerier;
// use crate::query::bank::BankQuerier;
use crate::query::compute::ComputeQuerier;

use crate::{
    account::Account,
    crypto::{self, Decrypter, Nonce},
    CodeHash, Result,
};

pub(crate) mod query;
pub(crate) mod tx;
pub mod types;

pub struct SecretNetworkClient {
    pub auth: AuthQuerier,
    pub compute: ComputeQuerier,
}

impl SecretNetworkClient {
    pub async fn new(url: impl Into<String>) -> Self {
        let url = url.into();

        let auth = AuthQuerier::new(&url).await.unwrap();
        let compute = ComputeQuerier::new(&url).await.unwrap();

        Self { auth, compute }
    }
}

pub struct Client {
    pub rpc: cosmrs::rpc::HttpClient,
    chain_id: String,
    enclave_pubk: crypto::Key,
}

impl Client {
    pub(crate) fn init(
        host: &str,
        port: u16,
        enclave_key: crypto::Key,
        chain_id: &str,
    ) -> Result<Self> {
        let rpc_url = format!("{}:{}", host, port);
        let rpc = cosmrs::rpc::HttpClient::new(rpc_url.as_str())?;

        Ok(Client {
            rpc,
            chain_id: chain_id.to_owned(),
            enclave_pubk: enclave_key,
        })
    }

    pub async fn block_height(&self) -> Result<u32> {
        let res = cosmrs::rpc::Client::latest_block(&self.rpc).await?;
        Ok(res.block.header.height.value() as _)
    }

    async fn enclave_public_key(&self) -> Result<crypto::Key> {
        Ok(self.enclave_pubk)
    }

    async fn encrypt_msg<M: serde::Serialize>(
        &self,
        msg: &M,
        code_hash: &CodeHash,
        account: &Account,
    ) -> Result<(Nonce, Vec<u8>)> {
        let msg = serde_json::to_vec(msg).expect("msg cannot be serialized as JSON");
        let plaintext = [code_hash.to_hex_string().as_bytes(), msg.as_slice()].concat();
        self.encrypt_msg_raw(&plaintext, account).await
    }

    async fn encrypt_msg_raw(&self, msg: &[u8], account: &Account) -> Result<(Nonce, Vec<u8>)> {
        let (prvk, pubk) = account.prv_pub_bytes();
        let io_key = self.enclave_public_key().await?;
        let nonce_ciphertext = crypto::encrypt(&prvk, &pubk, &io_key, msg)?;
        Ok(nonce_ciphertext)
    }

    async fn decrypter(&self, nonce: &Nonce, account: &Account) -> Result<Decrypter> {
        let (secret, _) = account.prv_pub_bytes();
        let io_key = self.enclave_public_key().await?;
        Ok(Decrypter::new(secret, io_key, *nonce))
    }
}
