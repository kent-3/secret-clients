use crate::{secret_client::ToAmino, wallet::wallet_amino::AminoMsg, Result};
use secretrs::{tx::Msg as CosmrsMsg, utils::encryption::SecretUtils, Any};
use serde::{Deserialize, Serialize};
use tracing::debug;

pub trait Msg<T: Serialize>: CosmrsMsg + ToAmino<T> {
    fn to_amino(&mut self, utils: impl SecretUtils) -> Result<AminoMsg<T>> {
        Ok(<Self as ToAmino<T>>::to_amino(&self))
    }
    fn to_proto(&mut self, utils: impl SecretUtils) -> Result<Any> {
        // It's safe to unwrap here because the only way it can fail is if the buffer given to
        // `encode` does not have sufficient capacity, but it's being given a Vec::new() which will
        // grow as needed.
        Ok(self.to_any()?)
    }
}

// pub trait NeedsEncryption: Sized {
//     fn encrypt(self, contract_code_hash: String, utils: impl SecretUtils) -> Result<Self>;
// }
//
// impl NeedsEncryption for MsgExecuteContract {
//     fn encrypt(mut self, contract_code_hash: String, utils: impl SecretUtils) -> Result<Self> {
//         let encrypted_msg = utils.encrypt(&contract_code_hash, &self.msg)?;
//         self.msg = encrypted_msg.into_inner();
//
//         Ok(self)
//     }
// }
// impl NeedsEncryption for MsgInstantiateContract {
//     fn encrypt(mut self, contract_code_hash: String, utils: impl SecretUtils) -> Result<Self> {
//         let encrypted_msg = utils.encrypt(&contract_code_hash, &self.init_msg)?;
//         self.init_msg = encrypted_msg.into_inner();
//
//         Ok(self)
//     }
// }
// impl NeedsEncryption for MsgMigrateContract {
//     fn encrypt(mut self, contract_code_hash: String, utils: impl SecretUtils) -> Result<Self> {
//         let encrypted_msg = utils.encrypt(&contract_code_hash, &self.msg)?;
//         self.msg = encrypted_msg.into_inner();
//
//         Ok(self)
//     }
// }
