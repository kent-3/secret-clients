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
use serde::{Deserialize, Serialize};
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

pub trait Msg<T: Serialize>: CosmrsMsg + ToAmino<T> {
    fn to_amino(&mut self, utils: impl Enigma) -> Result<AminoMsg<T>> {
        Ok(<Self as ToAmino<T>>::to_amino(&self))
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

pub trait ToAmino<T: Serialize> {
    fn to_amino(&self) -> AminoMsg<T>;
}

use crate::wallet::wallet_amino::CoinSerializable;

#[derive(Serialize, Deserialize, Debug)]
pub struct MsgExecuteContractAminoValue {
    sender: String,
    contract: String,
    msg: String,
    sent_funds: Vec<CoinSerializable>,
}

impl ToAmino<MsgExecuteContractAminoValue> for MsgExecuteContract {
    fn to_amino(&self) -> AminoMsg<MsgExecuteContractAminoValue> {
        let sent_funds = self
            .sent_funds
            .iter()
            .map(|coin| CoinSerializable::from(coin.clone()))
            .collect();
        AminoMsg {
            r#type: "wasm/MsgExecuteContract".to_string(),
            value: MsgExecuteContractAminoValue {
                sender: self.sender.to_string(),
                contract: self.contract.to_string(),
                msg: BASE64_STANDARD.encode(&self.msg),
                sent_funds,
            },
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct MsgInstantiateContractAminoValue {
    sender: String,
    contract: String,
    msg: String,
    sent_funds: Vec<CoinSerializable>,
}

impl ToAmino<MsgInstantiateContractAminoValue> for MsgInstantiateContract {
    fn to_amino(&self) -> AminoMsg<MsgInstantiateContractAminoValue> {
        // AminoMsg {
        //     r#type: "wasm/MsgInstantiateContract".to_string(),
        //     value: serde_json::json!({
        //         "sender": self.sender.to_string(),
        //         "code_id": self.code_id.to_string(),
        //         "label": self.label.to_string(),
        //         "init_msg": BASE64_STANDARD.encode(&self.init_msg), // the encrypted version
        //         "admin": self.admin
        //     }),
        // }
        todo!()
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct MsgMigrateContractAminoValue {
    sender: String,
    contract: String,
    msg: String,
    code_id: String,
}

impl ToAmino<MsgMigrateContractAminoValue> for MsgMigrateContract {
    fn to_amino(&self) -> AminoMsg<MsgMigrateContractAminoValue> {
        // AminoMsg {
        //     r#type: "wasm/MsgMigrateContract".to_string(),
        //     value: serde_json::json!({
        //         "sender": self.sender.to_string(),
        //         "contract": self.contract.to_string(),
        //         "msg": BASE64_STANDARD.encode(&self.msg), // the encrypted version
        //         "code_id": self.code_id.to_string(),
        //     }),
        // }
        todo!()
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct MsgStoreCodeAminoValue {
    sender: String,
    wasm_byte_code: String,
    source: String,
    builder: String,
}

impl ToAmino<MsgStoreCodeAminoValue> for MsgStoreCode {
    fn to_amino(&self) -> AminoMsg<MsgStoreCodeAminoValue> {
        // AminoMsg {
        //     r#type: "wasm/MsgStoreCode".to_string(),
        //     value: serde_json::json!({
        //         "sender": self.sender.to_string(),
        //         "wasm_byte_code": BASE64_STANDARD.encode(&self.wasm_byte_code),
        //         "source": self.source,
        //         "builder": self.builder
        //     }),
        // }
        todo!()
    }
}
