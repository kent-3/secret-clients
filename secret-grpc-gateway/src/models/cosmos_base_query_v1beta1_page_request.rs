/*
 * Secret Network
 *
 * A REST interface for queries and transactions
 *
 * The version of the OpenAPI document: v1.12
 *
 * Generated by: https://openapi-generator.tech
 */

/// CosmosBaseQueryV1beta1PageRequest : message SomeRequest {          Foo some_parameter = 1;          PageRequest pagination = 2;  }

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CosmosBaseQueryV1beta1PageRequest {
    /// key is a value returned in PageResponse.next_key to begin querying the next page most efficiently. Only one of offset or key should be set.
    #[serde(rename = "key", skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    /// offset is a numeric offset that can be used when key is unavailable. It is less efficient than using key. Only one of offset or key should be set.
    #[serde(rename = "offset", skip_serializing_if = "Option::is_none")]
    pub offset: Option<String>,
    /// limit is the total number of results to be returned in the result page. If left empty it will default to a value to be set by each app.
    #[serde(rename = "limit", skip_serializing_if = "Option::is_none")]
    pub limit: Option<String>,
    /// count_total is set to true  to indicate that the result set should include a count of the total number of items available for pagination in UIs. count_total is only respected when offset is used. It is ignored when key is set.
    #[serde(rename = "count_total", skip_serializing_if = "Option::is_none")]
    pub count_total: Option<bool>,
    /// reverse is set to true if results are to be returned in the descending order.  Since: cosmos-sdk 0.43
    #[serde(rename = "reverse", skip_serializing_if = "Option::is_none")]
    pub reverse: Option<bool>,
}

impl CosmosBaseQueryV1beta1PageRequest {
    /// message SomeRequest {          Foo some_parameter = 1;          PageRequest pagination = 2;  }
    pub fn new() -> CosmosBaseQueryV1beta1PageRequest {
        CosmosBaseQueryV1beta1PageRequest {
            key: None,
            offset: None,
            limit: None,
            count_total: None,
            reverse: None,
        }
    }
}
