#![allow(unused)]

use ::cosmrs::proto::cosmos::base::query::v1beta1::PageRequest;
use ::cosmrs::proto::cosmos::staking::v1beta1::*;
use ::cosmrs::Any;

use super::{try_decode_any, try_decode_response};
use crate::{Error, Result};

impl crate::Client {
    pub async fn staking_validator(
        &self,
        validator_addr: impl Into<String>,
    ) -> Result<::cosmrs::staking::QueryValidatorResponse> {
        let validator_addr = validator_addr.into();

        let path = "/cosmos.staking.v1beta1.Query/Validator";
        let msg = QueryValidatorRequest { validator_addr };

        self.query_with_msg(path, msg)
            .await
            .and_then(try_decode_response::<QueryValidatorResponse>)
            .and_then(|res| res.try_into().map_err(Error::from))
    }

    pub async fn staking_validators(
        &self,
        status: BondStatus,
        pagination: Option<PageRequest>,
    ) -> Result<::cosmrs::staking::QueryValidatorsResponse> {
        let status = status.as_str_name().to_owned();

        let path = "/cosmos.staking.v1beta1.Query/Validators";
        let msg = QueryValidatorsRequest { status, pagination };

        self.query_with_msg(path, msg)
            .await
            .and_then(try_decode_response::<QueryValidatorsResponse>)
            .and_then(|res| res.try_into().map_err(Error::from))
    }

    pub async fn staking_validator_delegations(
        &self,
        validator_addr: impl Into<String>,
        pagination: Option<PageRequest>,
    ) -> Result<QueryValidatorDelegationsResponse> {
        let validator_addr = validator_addr.into();

        let path = "/cosmos.staking.v1beta1.Query/ValidatorDelegations";
        let msg = QueryValidatorDelegationsRequest {
            validator_addr,
            pagination,
        };

        self.query_with_msg(path, msg)
            .await
            .and_then(try_decode_response::<QueryValidatorDelegationsResponse>)
    }

    pub async fn staking_validator_unbonding_delegations(
        &self,
        validator_addr: impl Into<String>,
        pagination: Option<PageRequest>,
    ) -> Result<QueryValidatorUnbondingDelegationsResponse> {
        let validator_addr = validator_addr.into();

        let path = "/cosmos.staking.v1beta1.Query/ValidatorUnbondingDelegations";
        let msg = QueryValidatorUnbondingDelegationsRequest {
            validator_addr,
            pagination,
        };

        self.query_with_msg(path, msg)
            .await
            .and_then(try_decode_response::<QueryValidatorUnbondingDelegationsResponse>)
    }

    pub async fn staking_delegation(
        &self,
        delegator_addr: impl Into<String>,
        validator_addr: impl Into<String>,
    ) -> Result<QueryDelegationResponse> {
        let delegator_addr = delegator_addr.into();
        let validator_addr = validator_addr.into();

        let path = "/cosmos.staking.v1beta1.Query/Delegation";
        let msg = QueryDelegationRequest {
            delegator_addr,
            validator_addr,
        };

        self.query_with_msg(path, msg)
            .await
            .and_then(try_decode_response::<QueryDelegationResponse>)
    }

    pub async fn staking_unbonding_delegation(
        &self,
        delegator_addr: impl Into<String>,
        validator_addr: impl Into<String>,
    ) -> Result<QueryUnbondingDelegationResponse> {
        let delegator_addr = delegator_addr.into();
        let validator_addr = validator_addr.into();

        let path = "/cosmos.staking.v1beta1.Query/UnbondingDelegation";
        let msg = QueryUnbondingDelegationRequest {
            delegator_addr,
            validator_addr,
        };

        self.query_with_msg(path, msg)
            .await
            .and_then(try_decode_response::<QueryUnbondingDelegationResponse>)
    }

    pub async fn staking_delegator_delegations(
        &self,
        delegator_addr: impl Into<String>,
        pagination: Option<PageRequest>,
    ) -> Result<QueryDelegatorDelegationsResponse> {
        let delegator_addr = delegator_addr.into();

        let path = "/cosmos.staking.v1beta1.Query/DelegatorDelegations";
        let msg = QueryDelegatorDelegationsRequest {
            delegator_addr,
            pagination,
        };

        self.query_with_msg(path, msg)
            .await
            .and_then(try_decode_response::<QueryDelegatorDelegationsResponse>)
    }

    pub async fn staking_delegator_unbonding_delegations(
        &self,
        delegator_addr: impl Into<String>,
        pagination: Option<PageRequest>,
    ) -> Result<QueryDelegatorUnbondingDelegationsResponse> {
        let delegator_addr = delegator_addr.into();

        let path = "/cosmos.staking.v1beta1.Query/DelegatorUnbondingDelegations";
        let msg = QueryDelegatorUnbondingDelegationsRequest {
            delegator_addr,
            pagination,
        };

        self.query_with_msg(path, msg)
            .await
            .and_then(try_decode_response::<QueryDelegatorUnbondingDelegationsResponse>)
    }

    pub async fn staking_redelegations(
        &self,
        delegator_addr: impl Into<String>,
        src_validator_addr: impl Into<String>,
        dst_validator_addr: impl Into<String>,
        pagination: Option<PageRequest>,
    ) -> Result<QueryRedelegationsResponse> {
        let delegator_addr = delegator_addr.into();
        let src_validator_addr = src_validator_addr.into();
        let dst_validator_addr = dst_validator_addr.into();

        let path = "/cosmos.staking.v1beta1.Query/Redelegations";
        let msg = QueryRedelegationsRequest {
            delegator_addr,
            src_validator_addr,
            dst_validator_addr,
            pagination,
        };

        self.query_with_msg(path, msg)
            .await
            .and_then(try_decode_response::<QueryRedelegationsResponse>)
    }

    pub async fn staking_delegator_validators(
        &self,
        delegator_addr: impl Into<String>,
        pagination: Option<PageRequest>,
    ) -> Result<QueryDelegatorValidatorsResponse> {
        let delegator_addr = delegator_addr.into();

        let path = "/cosmos.staking.v1beta1.Query/DelegatorValidators";
        let msg = QueryDelegatorValidatorsRequest {
            delegator_addr,
            pagination,
        };

        self.query_with_msg(path, msg)
            .await
            .and_then(try_decode_response::<QueryDelegatorValidatorsResponse>)
    }

    pub async fn staking_delegator_validator(
        &self,
        delegator_addr: impl Into<String>,
        validator_addr: impl Into<String>,
    ) -> Result<QueryDelegatorValidatorResponse> {
        let delegator_addr = delegator_addr.into();
        let validator_addr = validator_addr.into();

        let path = "/cosmos.staking.v1beta1.Query/DelegatorValidator";
        let msg = QueryDelegatorValidatorRequest {
            delegator_addr,
            validator_addr,
        };

        self.query_with_msg(path, msg)
            .await
            .and_then(try_decode_response::<QueryDelegatorValidatorResponse>)
    }

    pub async fn staking_historical_info(
        &self,
        height: impl Into<i64>,
    ) -> Result<::cosmrs::staking::QueryHistoricalInfoResponse> {
        let height = height.into();

        let path = "/cosmos.staking.v1beta1.Query/HistoricalInfo";
        let msg = QueryHistoricalInfoRequest { height };

        self.query_with_msg(path, msg)
            .await
            .and_then(try_decode_response::<QueryHistoricalInfoResponse>)
            // I believe the point of this conversion is to add methods defined in `cosmrs`
            // (particularly to the `Header` type)
            .and_then(|res| res.try_into().map_err(Error::from))
    }

    pub async fn staking_pool(&self) -> Result<QueryPoolResponse> {
        let path = "/cosmos.staking.v1beta1.Query/Pool";
        let msg = QueryPoolRequest {};

        self.query_with_msg(path, msg)
            .await
            .and_then(try_decode_response::<QueryPoolResponse>)
    }

    pub async fn staking_params(&self) -> Result<QueryParamsResponse> {
        let path = "/cosmos.staking.v1beta1.Query/Params";
        let msg = QueryParamsRequest {};

        self.query_with_msg(path, msg)
            .await
            .and_then(try_decode_response::<QueryParamsResponse>)
    }
}
