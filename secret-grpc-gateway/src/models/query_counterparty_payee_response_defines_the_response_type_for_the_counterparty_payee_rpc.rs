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
pub struct QueryCounterpartyPayeeResponseDefinesTheResponseTypeForTheCounterpartyPayeeRpc {
    #[serde(rename = "counterparty_payee", skip_serializing_if = "Option::is_none")]
    pub counterparty_payee: Option<String>,
}

impl QueryCounterpartyPayeeResponseDefinesTheResponseTypeForTheCounterpartyPayeeRpc {
    pub fn new() -> QueryCounterpartyPayeeResponseDefinesTheResponseTypeForTheCounterpartyPayeeRpc {
        QueryCounterpartyPayeeResponseDefinesTheResponseTypeForTheCounterpartyPayeeRpc {
            counterparty_payee: None,
        }
    }
}
