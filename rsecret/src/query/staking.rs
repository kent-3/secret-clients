use crate::CreateClientOptions;
use crate::{Error, Result};
pub use secretrs::{
    grpc_clients::StakingQueryClient,
    proto::cosmos::{
        base::query::v1beta1::PageRequest,
        staking::v1beta1::{
            BondStatus, DelegationResponse, HistoricalInfo, Params, Pool, QueryDelegationRequest,
            QueryDelegationResponse, QueryDelegatorDelegationsRequest,
            QueryDelegatorDelegationsResponse, QueryDelegatorUnbondingDelegationsRequest,
            QueryDelegatorUnbondingDelegationsResponse, QueryDelegatorValidatorRequest,
            QueryDelegatorValidatorResponse, QueryDelegatorValidatorsRequest,
            QueryDelegatorValidatorsResponse, QueryHistoricalInfoRequest,
            QueryHistoricalInfoResponse, QueryParamsRequest, QueryParamsResponse, QueryPoolRequest,
            QueryPoolResponse, QueryRedelegationsRequest, QueryRedelegationsResponse,
            QueryUnbondingDelegationRequest, QueryUnbondingDelegationResponse,
            QueryValidatorDelegationsRequest, QueryValidatorDelegationsResponse,
            QueryValidatorRequest, QueryValidatorResponse,
            QueryValidatorUnbondingDelegationsRequest, QueryValidatorUnbondingDelegationsResponse,
            QueryValidatorsRequest, QueryValidatorsResponse, RedelegationResponse,
            UnbondingDelegation, Validator,
        },
    },
    tendermint::block::Height,
};
use tonic::{
    body::BoxBody,
    client::GrpcService,
    codegen::{Body, Bytes, StdError},
};
use tracing::{debug, warn};

#[derive(Debug, Clone)]
pub struct StakingQuerier<T> {
    pub(crate) inner: StakingQueryClient<T>,
}

#[cfg(not(target_arch = "wasm32"))]
impl StakingQuerier<::tonic::transport::Channel> {
    // pub async fn connect(options: &CreateClientOptions) -> Result<Self> {
    //     let channel = tonic::transport::Channel::from_static(options.url)
    //         .connect()
    //         .await?;
    //     Ok(Self::new(channel))
    // }
    pub fn new(channel: ::tonic::transport::Channel) -> Self {
        let inner = StakingQueryClient::new(channel);
        Self { inner }
    }
}

#[cfg(target_arch = "wasm32")]
impl StakingQuerier<::tonic_web_wasm_client::Client> {
    pub fn new(client: ::tonic_web_wasm_client::Client) -> Self {
        let inner = StakingQueryClient::new(client);
        Self { inner }
    }
}

impl<T> StakingQuerier<T>
where
    T: GrpcService<BoxBody> + Clone,
    T::Error: Into<StdError>,
    T::ResponseBody: Body<Data = Bytes> + Send + 'static,
    <T::ResponseBody as Body>::Error: Into<StdError> + Send,
{
    pub async fn validators(
        &self,
        status: BondStatus,
        pagination: Option<PageRequest>,
    ) -> Result<Vec<Validator>> {
        let mut all_validators = Vec::new();
        let mut current_page = pagination;
        let mut total_pages: Option<u64> = None;

        loop {
            let request = QueryValidatorsRequest {
                status: status.as_str_name().to_string(),
                pagination: current_page.clone(),
            };
            let response = self.inner.clone().validators(request).await?;
            let response = response.into_inner();
            let validators = response.validators;
            all_validators.extend(validators);

            if let Some(page_response) = response.pagination {
                debug!("{:?}", current_page.as_ref().unwrap());
                debug!("{:?}", page_response);
                if total_pages.is_none() && page_response.total > 0 {
                    let total_count = page_response.total;
                    let limit = current_page.as_ref().unwrap().limit;
                    total_pages = Some((total_count + limit - 1) / limit);
                    debug!("Total pages needed: {}", total_pages.unwrap());
                    if total_pages.unwrap() > 10 {
                        warn!("That's a lot of pages!");
                    }
                }
                if page_response.next_key.is_empty() {
                    break;
                } else {
                    current_page = Some(PageRequest {
                        key: page_response.next_key,
                        ..current_page.unwrap_or_default()
                    });
                }
            } else {
                break;
            }
        }

        Ok(all_validators)
    }

    pub async fn validator(&self, validator_addr: impl Into<String>) -> Result<Validator> {
        let validator_addr = validator_addr.into();
        let request = QueryValidatorRequest { validator_addr };
        let response: ::tonic::Response<QueryValidatorResponse> =
            self.inner.clone().validator(request).await?;

        // TODO: think of a better error message. something like "no validator with that address"
        let validator = response
            .into_inner()
            .validator
            .ok_or(Error::MissingField { name: "validator" })?;
        Ok(validator)
    }

    pub async fn validator_delegations(
        &self,
        validator_addr: impl Into<String>,
        pagination: Option<PageRequest>,
    ) -> Result<Vec<DelegationResponse>> {
        let validator_addr = validator_addr.into();

        let mut all_delegation_responses = Vec::new();
        let mut current_page = pagination;

        loop {
            let request = QueryValidatorDelegationsRequest {
                validator_addr: validator_addr.clone(),
                pagination: current_page.clone(),
            };
            let response: ::tonic::Response<QueryValidatorDelegationsResponse> =
                self.inner.clone().validator_delegations(request).await?;
            let response = response.into_inner();
            let delegation_responses = response.delegation_responses;
            all_delegation_responses.extend(delegation_responses);

            if let Some(page_response) = response.pagination {
                if page_response.next_key.is_empty() {
                    break;
                } else {
                    current_page = Some(PageRequest {
                        key: page_response.next_key,
                        ..current_page.unwrap_or_default()
                    });
                }
            } else {
                break;
            }
        }
        Ok(all_delegation_responses)
    }

    pub async fn validator_unbonding_delegations(
        &self,
        validator_addr: impl Into<String>,
        pagination: Option<PageRequest>,
    ) -> Result<Vec<UnbondingDelegation>> {
        let validator_addr = validator_addr.into();
        let request = QueryValidatorUnbondingDelegationsRequest {
            validator_addr: validator_addr.clone(),
            pagination: pagination.clone(),
        };
        let response: ::tonic::Response<QueryValidatorUnbondingDelegationsResponse> = self
            .inner
            .clone()
            .validator_unbonding_delegations(request)
            .await?;

        // TODO: check pagination works
        let response = response.into_inner();
        let mut unbonding_responses = response.unbonding_responses;
        if let Some(page_request) = pagination {
            if let Some(page_response) = response.pagination {
                if !page_response.next_key.is_empty() {
                    let next_page = PageRequest {
                        key: page_response.next_key,
                        ..page_request
                    };
                    let more_unbonding_responses = self
                        .validator_unbonding_delegations(validator_addr, Some(next_page))
                        .await?;
                    unbonding_responses.extend(more_unbonding_responses);
                }
            }
        }
        Ok(unbonding_responses)
    }

    pub async fn delegation(
        &self,
        delegator_addr: impl Into<String>,
        validator_addr: impl Into<String>,
    ) -> Result<DelegationResponse> {
        let delegator_addr = delegator_addr.into();
        let validator_addr = validator_addr.into();

        let request = QueryDelegationRequest {
            delegator_addr,
            validator_addr,
        };
        let response: ::tonic::Response<QueryDelegationResponse> =
            self.inner.clone().delegation(request).await?;

        let delegation = response
            .into_inner()
            .delegation_response
            .ok_or(Error::MissingField {
                name: "delegation_response",
            })?;
        Ok(delegation)
    }

    pub async fn unbonding_delegation(
        &self,
        delegator_addr: impl Into<String>,
        validator_addr: impl Into<String>,
    ) -> Result<UnbondingDelegation> {
        let delegator_addr = delegator_addr.into();
        let validator_addr = validator_addr.into();

        let request = QueryUnbondingDelegationRequest {
            delegator_addr,
            validator_addr,
        };
        let response: ::tonic::Response<QueryUnbondingDelegationResponse> =
            self.inner.clone().unbonding_delegation(request).await?;

        let unbonding_delegation = response
            .into_inner()
            .unbond
            .ok_or(Error::MissingField { name: "unbond" })?;
        Ok(unbonding_delegation)
    }

    pub async fn delegator_delegations(
        &self,
        delegator_addr: impl Into<String>,
        pagination: Option<PageRequest>,
    ) -> Result<Vec<DelegationResponse>> {
        let delegator_addr = delegator_addr.into();

        let request = QueryDelegatorDelegationsRequest {
            delegator_addr: delegator_addr.clone(),
            pagination: pagination.clone(),
        };
        let response: ::tonic::Response<QueryDelegatorDelegationsResponse> =
            self.inner.clone().delegator_delegations(request).await?;

        // TODO: check pagination works
        let response = response.into_inner();
        let mut delegation_responses = response.delegation_responses;
        if let Some(page_request) = pagination {
            if let Some(page_response) = response.pagination {
                if !page_response.next_key.is_empty() {
                    let next_page = PageRequest {
                        key: page_response.next_key,
                        ..page_request
                    };
                    let more_delegation_responses = self
                        .delegator_delegations(delegator_addr, Some(next_page))
                        .await?;
                    delegation_responses.extend(more_delegation_responses);
                }
            }
        }
        Ok(delegation_responses)
    }

    pub async fn delegator_unbonding_delegations(
        &self,
        delegator_addr: impl Into<String>,
        pagination: Option<PageRequest>,
    ) -> Result<Vec<UnbondingDelegation>> {
        let delegator_addr = delegator_addr.into();

        let request = QueryDelegatorUnbondingDelegationsRequest {
            delegator_addr: delegator_addr.clone(),
            pagination: pagination.clone(),
        };
        let response: ::tonic::Response<QueryDelegatorUnbondingDelegationsResponse> = self
            .inner
            .clone()
            .delegator_unbonding_delegations(request)
            .await?;

        // TODO: check pagination works
        let response = response.into_inner();
        let mut unbonding_responses = response.unbonding_responses;
        if let Some(page_request) = pagination {
            if let Some(page_response) = response.pagination {
                if !page_response.next_key.is_empty() {
                    let next_page = PageRequest {
                        key: page_response.next_key,
                        ..page_request
                    };
                    let more_unbonding_responses = self
                        .delegator_unbonding_delegations(delegator_addr, Some(next_page))
                        .await?;
                    unbonding_responses.extend(more_unbonding_responses);
                }
            }
        }
        Ok(unbonding_responses)
    }

    pub async fn redelegations(
        &self,
        delegator_addr: impl Into<String>,
        src_validator_addr: impl Into<String>,
        dst_validator_addr: impl Into<String>,
        pagination: Option<PageRequest>,
    ) -> Result<Vec<RedelegationResponse>> {
        let delegator_addr = delegator_addr.into();
        let src_validator_addr = src_validator_addr.into();
        let dst_validator_addr = dst_validator_addr.into();

        let request = QueryRedelegationsRequest {
            delegator_addr: delegator_addr.clone(),
            src_validator_addr: src_validator_addr.clone(),
            dst_validator_addr: dst_validator_addr.clone(),
            pagination: pagination.clone(),
        };
        let response: ::tonic::Response<QueryRedelegationsResponse> =
            self.inner.clone().redelegations(request).await?;

        // TODO: check pagination works
        let response = response.into_inner();
        let mut redelegations = response.redelegation_responses;
        if let Some(page_request) = pagination {
            if let Some(page_response) = response.pagination {
                if !page_response.next_key.is_empty() {
                    let next_page = PageRequest {
                        key: page_response.next_key,
                        ..page_request
                    };
                    let more_redelegations = self
                        .redelegations(
                            delegator_addr,
                            src_validator_addr,
                            dst_validator_addr,
                            Some(next_page),
                        )
                        .await?;
                    redelegations.extend(more_redelegations);
                }
            }
        }
        Ok(redelegations)
    }

    pub async fn delegator_validators(
        &self,
        delegator_addr: impl Into<String>,
        pagination: Option<PageRequest>,
    ) -> Result<Vec<Validator>> {
        let delegator_addr = delegator_addr.into();

        let request = QueryDelegatorValidatorsRequest {
            delegator_addr: delegator_addr.clone(),
            pagination: pagination.clone(),
        };
        let response: ::tonic::Response<QueryDelegatorValidatorsResponse> =
            self.inner.clone().delegator_validators(request).await?;

        // TODO: check pagination works
        let response = response.into_inner();
        let mut validators = response.validators;
        if let Some(page_request) = pagination {
            if let Some(page_response) = response.pagination {
                if !page_response.next_key.is_empty() {
                    let next_page = PageRequest {
                        key: page_response.next_key,
                        ..page_request
                    };
                    let more_validators = self
                        .delegator_validators(delegator_addr, Some(next_page))
                        .await?;
                    validators.extend(more_validators);
                }
            }
        }
        Ok(validators)
    }

    pub async fn delegator_validator(
        &self,
        delegator_addr: impl Into<String>,
        validator_addr: impl Into<String>,
    ) -> Result<Validator> {
        let delegator_addr = delegator_addr.into();
        let validator_addr = validator_addr.into();

        let request = QueryDelegatorValidatorRequest {
            delegator_addr,
            validator_addr,
        };
        let response: ::tonic::Response<QueryDelegatorValidatorResponse> =
            self.inner.clone().delegator_validator(request).await?;

        // TODO: think of a better error message. something like "no validator with that address"
        let validator = response
            .into_inner()
            .validator
            .ok_or(Error::MissingField { name: "validator" })?;
        Ok(validator)
    }

    pub async fn historical_info(&self, height: impl Into<Height>) -> Result<HistoricalInfo> {
        let height = i64::from(height.into());
        let request = QueryHistoricalInfoRequest { height };
        let response: ::tonic::Response<QueryHistoricalInfoResponse> =
            self.inner.clone().historical_info(request).await?;

        let historical_info = response
            .into_inner()
            .hist
            .ok_or(Error::MissingField { name: "hist" })?;
        Ok(historical_info)
    }

    pub async fn pool(&self) -> Result<Pool> {
        let request = QueryPoolRequest {};
        let response: ::tonic::Response<QueryPoolResponse> =
            self.inner.clone().pool(request).await?;

        let pool = response
            .into_inner()
            .pool
            .ok_or(Error::MissingField { name: "pool" })?;
        Ok(pool)
    }

    pub async fn params(&self) -> Result<Params> {
        let request = QueryParamsRequest {};
        let response: ::tonic::Response<QueryParamsResponse> =
            self.inner.clone().params(request).await?;

        let params = response
            .into_inner()
            .params
            .ok_or(Error::MissingField { name: "params" })?;
        Ok(params)
    }
}
