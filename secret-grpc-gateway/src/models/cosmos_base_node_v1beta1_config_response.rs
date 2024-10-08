/*
 * Secret Network
 *
 * A REST interface for queries and transactions
 *
 * The version of the OpenAPI document: v1.12
 *
 * Generated by: https://openapi-generator.tech
 */

/// CosmosBaseNodeV1beta1ConfigResponse : ConfigResponse defines the response structure for the Config gRPC query.

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CosmosBaseNodeV1beta1ConfigResponse {
    #[serde(rename = "minimum_gas_price", skip_serializing_if = "Option::is_none")]
    pub minimum_gas_price: Option<String>,
}

impl CosmosBaseNodeV1beta1ConfigResponse {
    /// ConfigResponse defines the response structure for the Config gRPC query.
    pub fn new() -> CosmosBaseNodeV1beta1ConfigResponse {
        CosmosBaseNodeV1beta1ConfigResponse {
            minimum_gas_price: None,
        }
    }
}
