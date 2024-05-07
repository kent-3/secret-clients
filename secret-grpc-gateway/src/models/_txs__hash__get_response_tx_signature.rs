/*
 * Secret Network
 *
 * A REST interface for queries and transactions
 *
 * The version of the OpenAPI document: v1.12
 *
 * Generated by: https://openapi-generator.tech
 */

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct TxsHashGetResponseTxSignature {
    #[serde(rename = "signature", skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
    #[serde(rename = "pub_key", skip_serializing_if = "Option::is_none")]
    pub pub_key: Option<Box<crate::models::TxsHashGetResponseTxSignaturePubKey>>,
    #[serde(rename = "account_number", skip_serializing_if = "Option::is_none")]
    pub account_number: Option<String>,
    #[serde(rename = "sequence", skip_serializing_if = "Option::is_none")]
    pub sequence: Option<String>,
}

impl TxsHashGetResponseTxSignature {
    pub fn new() -> TxsHashGetResponseTxSignature {
        TxsHashGetResponseTxSignature {
            signature: None,
            pub_key: None,
            account_number: None,
            sequence: None,
        }
    }
}
