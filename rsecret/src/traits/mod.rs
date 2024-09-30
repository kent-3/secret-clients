use crate::wallet::wallet_amino::AminoMsg;
use crate::Result;

use base64::prelude::{Engine, BASE64_STANDARD};
use secretrs::{
    compute::{MsgExecuteContract, MsgInstantiateContract, MsgMigrateContract, MsgStoreCode},
    tx::Msg as CosmrsMsg,
    Any, EncryptionUtils,
};
use serde_json::Value;

fn is_plaintext(message: &[u8]) -> bool {
    serde_json::from_slice::<Value>(message).is_ok()
}

// Marker trait for identifying messages that require encryption.
trait NeedsEncryption {}

impl NeedsEncryption for secretrs::compute::MsgExecuteContract {}
impl NeedsEncryption for secretrs::compute::MsgInstantiateContract {}
impl NeedsEncryption for secretrs::compute::MsgMigrateContract {}

pub trait Msg: CosmrsMsg {
    fn to_amino(&mut self, utils: EncryptionUtils) -> Result<AminoMsg>;
    fn to_proto(&mut self, utils: EncryptionUtils) -> Result<Any>;
}

// NOTE: the "msg" used here needs to be the encrypted message. We can get away with this by
// encrypting and mutating the msg field in place before encoding.
impl Msg for MsgExecuteContract {
    fn to_amino(&mut self, utils: EncryptionUtils) -> Result<AminoMsg> {
        if is_plaintext(&self.msg) {
            let encrypted = utils.encrypt(todo!("&self.code_hash"), &self.msg)?;
            self.msg = encrypted.into_inner();
        }

        Ok(AminoMsg {
            r#type: "wasm/MsgExecuteContract".to_string(),
            value: serde_json::json!({
                "sender": self.sender.to_string(),
                "contract": self.contract.to_string(),
                "msg": BASE64_STANDARD.encode(&self.msg),
                "sent_funds": self.sent_funds
            }),
        })
    }

    fn to_proto(&mut self, utils: EncryptionUtils) -> Result<Any> {
        if is_plaintext(&self.msg) {
            let encrypted = utils.encrypt(todo!("&self.code_hash"), &self.msg)?;
            self.msg = encrypted.into_inner();
        }

        Ok(self.clone().into_any()?)
    }
}

// impl Msg for MsgInstantiateContract {
//     fn to_amino(&mut self) -> AminoMsg {
//         AminoMsg {
//             r#type: "wasm/MsgInstantiateContract".to_string(),
//             value: serde_json::json!({
//                 "sender": self.sender.to_string(),
//                 "code_id": self.code_id.to_string(),
//                 "label": self.label.to_string(),
//                 "init_msg": BASE64_STANDARD.encode(&self.init_msg), // the encrypted version
//                 "admin": self.admin
//             }),
//         }
//     }
// }
//
// impl Msg for MsgMigrateContract {
//     fn to_amino(&mut self) -> AminoMsg {
//         AminoMsg {
//             r#type: "wasm/MsgMigrateContract".to_string(),
//             value: serde_json::json!({
//                 "sender": self.sender.to_string(),
//                 "contract": self.contract.to_string(),
//                 "msg": BASE64_STANDARD.encode(&self.msg), // the encrypted version
//                 "code_id": self.code_id.to_string(),
//             }),
//         }
//     }
// }
//
// impl Msg for MsgStoreCode {
//     fn to_amino(&mut self) -> AminoMsg {
//         AminoMsg {
//             r#type: "wasm/MsgStoreCode".to_string(),
//             value: serde_json::json!({
//                 "sender": self.sender.to_string(),
//                 "wasm_byte_code": BASE64_STANDARD.encode(&self.wasm_byte_code),
//                 "source": self.source,
//                 "builder": self.builder
//             }),
//         }
//     }
// }
