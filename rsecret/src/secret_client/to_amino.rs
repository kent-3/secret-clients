use crate::{wallet::wallet_amino::AminoMsg, Result};
use base64::prelude::{Engine, BASE64_STANDARD};
use secretrs::compute::{
    MsgExecuteContract, MsgInstantiateContract, MsgMigrateContract, MsgStoreCode,
};
use serde::{Deserialize, Serialize};
use tracing::debug;

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
