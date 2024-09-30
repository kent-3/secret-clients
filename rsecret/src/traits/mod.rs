#[allow(unused)]
use crate::wallet::wallet_amino::AminoMsg;
use base64::prelude::{Engine, BASE64_STANDARD};
use secretrs::{
    compute::{MsgExecuteContract, MsgInstantiateContract, MsgMigrateContract, MsgStoreCode},
    tx::Msg as CosmrsMsg,
};
use serde_json::Value;

pub fn is_plaintext(message: &[u8]) -> Result<(), crate::Error> {
    match serde_json::from_slice::<Value>(message) {
        Ok(_) => Ok(()),
        Err(_) => Err(crate::Error::custom(
            "you need to encrypt the message first!",
        )),
    }
}

pub trait Msg: CosmrsMsg + ToAmino {}
impl<T: CosmrsMsg + ToAmino> Msg for T {}

pub trait NeedsEncryption {}
impl NeedsEncryption for secretrs::compute::MsgExecuteContract {}
impl NeedsEncryption for secretrs::compute::MsgInstantiateContract {}
impl NeedsEncryption for secretrs::compute::MsgMigrateContract {}

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
