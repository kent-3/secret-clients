#![allow(unused)]

use crate::wallet::wallet_amino::AminoMsg;
use crate::Result;
use base64::prelude::{Engine, BASE64_STANDARD};
use secretrs::{
    compute::{MsgExecuteContract, MsgInstantiateContract, MsgMigrateContract, MsgStoreCode},
    tx::Msg as CosmrsMsg,
    utils::encryption::Enigma,
    Any,
};
use serde_json::Value;
use std::any::TypeId;
use tracing::debug;

pub fn is_plaintext(message: &[u8]) -> Result<(), crate::Error> {
    match serde_json::from_slice::<Value>(message) {
        Ok(_) => Ok(()),
        Err(_) => Err(crate::Error::custom(
            "you need to encrypt the message first!",
        )),
    }
}

pub trait Msg: CosmrsMsg + ToAmino {
    fn to_amino(&mut self, utils: impl Enigma) -> Result<AminoMsg> {
        Ok(<Self as ToAmino>::to_amino(&self))
    }
    fn to_proto(&mut self, utils: impl Enigma) -> Result<Any> {
        // It's safe to unwrap here because the only way it can fail is if the buffer given to
        // `encode` does not have sufficient capacity, but it's being given a Vec::new() which will
        // grow as needed.
        Ok(self.to_any()?)
    }
}

// pub trait NeedsEncryption: Sized {
//     fn encrypt(self, contract_code_hash: String, utils: impl Enigma) -> Result<Self>;
// }
//
// impl NeedsEncryption for MsgExecuteContract {
//     fn encrypt(mut self, contract_code_hash: String, utils: impl Enigma) -> Result<Self> {
//         let encrypted_msg = utils.encrypt(&contract_code_hash, &self.msg)?;
//         self.msg = encrypted_msg.into_inner();
//
//         Ok(self)
//     }
// }
// impl NeedsEncryption for MsgInstantiateContract {
//     fn encrypt(mut self, contract_code_hash: String, utils: impl Enigma) -> Result<Self> {
//         let encrypted_msg = utils.encrypt(&contract_code_hash, &self.init_msg)?;
//         self.init_msg = encrypted_msg.into_inner();
//
//         Ok(self)
//     }
// }
// impl NeedsEncryption for MsgMigrateContract {
//     fn encrypt(mut self, contract_code_hash: String, utils: impl Enigma) -> Result<Self> {
//         let encrypted_msg = utils.encrypt(&contract_code_hash, &self.msg)?;
//         self.msg = encrypted_msg.into_inner();
//
//         Ok(self)
//     }
// }

pub trait ToAmino {
    fn to_amino(&self) -> AminoMsg;
}

impl ToAmino for MsgExecuteContract {
    fn to_amino(&self) -> AminoMsg {
        AminoMsg {
            r#type: "wasm/MsgExecuteContract".to_string(),
            value: serde_json::json!({
                "sender": self.sender.to_string(),
                "contract": self.contract.to_string(),
                "msg": BASE64_STANDARD.encode(&self.msg),
                "sent_funds": self.sent_funds
            }),
        }
    }
}

impl ToAmino for MsgInstantiateContract {
    fn to_amino(&self) -> AminoMsg {
        AminoMsg {
            r#type: "wasm/MsgInstantiateContract".to_string(),
            value: serde_json::json!({
                "sender": self.sender.to_string(),
                "code_id": self.code_id.to_string(),
                "label": self.label.to_string(),
                "init_msg": BASE64_STANDARD.encode(&self.init_msg), // the encrypted version
                "admin": self.admin
            }),
        }
    }
}

impl ToAmino for MsgMigrateContract {
    fn to_amino(&self) -> AminoMsg {
        AminoMsg {
            r#type: "wasm/MsgMigrateContract".to_string(),
            value: serde_json::json!({
                "sender": self.sender.to_string(),
                "contract": self.contract.to_string(),
                "msg": BASE64_STANDARD.encode(&self.msg), // the encrypted version
                "code_id": self.code_id.to_string(),
            }),
        }
    }
}

impl ToAmino for MsgStoreCode {
    fn to_amino(&self) -> AminoMsg {
        AminoMsg {
            r#type: "wasm/MsgStoreCode".to_string(),
            value: serde_json::json!({
                "sender": self.sender.to_string(),
                "wasm_byte_code": BASE64_STANDARD.encode(&self.wasm_byte_code),
                "source": self.source,
                "builder": self.builder
            }),
        }
    }
}
