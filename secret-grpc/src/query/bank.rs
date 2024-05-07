#![allow(unused)]

// TODO - Add query methods:
// DenomsMetadata, SupplyOf, SpendableBalances

use ::cosmrs::proto::cosmos::bank::v1beta1::*;
use ::cosmrs::proto::cosmos::base::query::v1beta1::PageRequest;
use ::cosmrs::proto::cosmos::base::v1beta1::Coin;

use super::{try_decode_any, try_decode_response};
use crate::{Error, Result};

impl crate::Client {
    /// `/cosmos.bank.v1beta1.Query/Balance`: get balance of a specific denom
    pub async fn bank_balance(
        &self,
        address: impl Into<String>,
        denom: impl Into<String>,
    ) -> Result<Coin> {
        let address = address.into();
        let denom = denom.into();

        let path = "/cosmos.bank.v1beta1.Query/Balance";
        let msg = QueryBalanceRequest { address, denom };

        self.query_with_msg(path, msg)
            .await
            .and_then(try_decode_response::<QueryBalanceResponse>)
            .and_then(|res| {
                res.balance
                    .ok_or(Error::AbciQuery("no balance".to_string()))
            })
    }

    // TODO - more work needed here to handle the response and pagination...
    /// `/cosmos.bank.v1beta1.Query/AllBalances`: get balances of all denoms
    pub async fn bank_all_balances(
        &self,
        address: impl Into<String>,
        pagination: Option<PageRequest>,
    ) -> Result<QueryAllBalancesResponse> {
        let address = address.into();

        let path = "/cosmos.bank.v1beta1.Query/AllBalances";
        let msg = QueryAllBalancesRequest {
            address,
            pagination,
        };

        self.query_with_msg(path, msg)
            .await
            .and_then(try_decode_response::<QueryAllBalancesResponse>)
    }

    // TODO - more work needed here to handle the response and pagination...
    /// `/cosmos.bank.v1beta1.Query/TotalSupply`: get the total supply of all denoms
    pub async fn bank_total_supply(
        &self,
        pagination: Option<PageRequest>,
    ) -> Result<QueryTotalSupplyResponse> {
        let path = "/cosmos.bank.v1beta1.Query/TotalSupply";
        let msg = QueryTotalSupplyRequest { pagination };

        self.query_with_msg(path, msg)
            .await
            .and_then(try_decode_response::<QueryTotalSupplyResponse>)
    }

    /// `/cosmos.bank.v1beta1.Query/Params`: get the parameters of the bank module
    pub async fn bank_params(&self) -> Result<Params> {
        let path = "/cosmos.bank.v1beta1.Query/Params";
        let msg = QueryParamsRequest {};

        self.query_with_msg(path, msg)
            .await
            .and_then(try_decode_response::<QueryParamsResponse>)
            .and_then(|res| {
                res.params
                    .ok_or(Error::AbciQuery("empty params".to_string()))
            })
    }

    /// `/cosmos.bank.v1beta1.Query/DenomMetadata`: get metadata about a specific denom
    ///
    /// Note! Not all denoms have this.
    pub async fn bank_denom_metadata(
        &self,
        denom: impl Into<String>,
    ) -> Result<QueryDenomMetadataResponse> {
        let denom = denom.into();

        let path = "/cosmos.bank.v1beta1.Query/DenomMetadata";
        let msg = QueryDenomMetadataRequest { denom };

        self.query_with_msg(path, msg)
            .await
            .and_then(try_decode_response::<QueryDenomMetadataResponse>)
    }
}
