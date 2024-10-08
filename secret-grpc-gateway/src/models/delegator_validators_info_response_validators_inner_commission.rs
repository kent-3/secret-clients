/*
 * Secret Network
 *
 * A REST interface for queries and transactions
 *
 * The version of the OpenAPI document: v1.12
 *
 * Generated by: https://openapi-generator.tech
 */

/// DelegatorValidatorsInfoResponseValidatorsInnerCommission : commission defines the commission parameters.

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DelegatorValidatorsInfoResponseValidatorsInnerCommission {
    #[serde(rename = "commission_rates", skip_serializing_if = "Option::is_none")]
    pub commission_rates: Option<
        Box<crate::models::DelegatorValidatorsInfoResponseValidatorsInnerCommissionCommissionRates>,
    >,
    /// update_time is the last time the commission rate was changed.
    #[serde(rename = "update_time", skip_serializing_if = "Option::is_none")]
    pub update_time: Option<String>,
}

impl DelegatorValidatorsInfoResponseValidatorsInnerCommission {
    /// commission defines the commission parameters.
    pub fn new() -> DelegatorValidatorsInfoResponseValidatorsInnerCommission {
        DelegatorValidatorsInfoResponseValidatorsInnerCommission {
            commission_rates: None,
            update_time: None,
        }
    }
}
