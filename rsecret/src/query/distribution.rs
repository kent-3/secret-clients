use crate::{Error, Result};
use prost::Message;
pub use secretrs::{
    grpc_clients::DistributionQueryClient,
    proto::cosmos::{
        base::query::v1beta1::{PageRequest, PageResponse},
        base::v1beta1::DecCoin,
        distribution::v1beta1::*,
    },
};
use tonic::{
    body::BoxBody,
    client::GrpcService,
    codegen::{Body, Bytes, StdError},
};
use tracing::{debug, info, warn};

#[derive(Debug, Clone)]
pub struct DistributionQuerier<T> {
    inner: DistributionQueryClient<T>,
}

#[cfg(not(target_arch = "wasm32"))]
impl DistributionQuerier<::tonic::transport::Channel> {
    pub fn new(channel: ::tonic::transport::Channel) -> Self {
        let inner = DistributionQueryClient::new(channel);
        Self { inner }
    }
}

#[cfg(target_arch = "wasm32")]
impl DistributionQuerier<::tonic_web_wasm_client::Client> {
    pub fn new(client: ::tonic_web_wasm_client::Client) -> Self {
        let inner = DistributionQueryClient::new(client);
        Self { inner }
    }
}

impl<T> DistributionQuerier<T>
where
    T: GrpcService<BoxBody> + Clone,
    T::Error: Into<StdError>,
    T::ResponseBody: Body<Data = Bytes> + Send + 'static,
    <T::ResponseBody as Body>::Error: Into<StdError> + Send,
{
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

    pub async fn validator_outstanding_rewards(
        &self,
        validator_address: impl Into<String>,
    ) -> Result<ValidatorOutstandingRewards> {
        let validator_address = validator_address.into();

        let request = QueryValidatorOutstandingRewardsRequest { validator_address };
        let response: ::tonic::Response<QueryValidatorOutstandingRewardsResponse> = self
            .inner
            .clone()
            .validator_outstanding_rewards(request)
            .await?;

        let rewards = response
            .into_inner()
            .rewards
            .ok_or(Error::MissingField { name: "rewards" })?;

        Ok(rewards)
    }

    pub async fn validator_commission(
        &self,
        validator_address: impl Into<String>,
    ) -> Result<ValidatorAccumulatedCommission> {
        let validator_address = validator_address.into();

        let request = QueryValidatorCommissionRequest { validator_address };
        let response: ::tonic::Response<QueryValidatorCommissionResponse> =
            self.inner.clone().validator_commission(request).await?;

        let commission = response
            .into_inner()
            .commission
            .ok_or(Error::MissingField { name: "commission" })?;

        Ok(commission)
    }

    pub async fn validator_slashes(
        &self,
        validator_address: impl Into<String>,
        starting_height: u64,
        ending_height: u64,
        pagination: Option<PageRequest>,
    ) -> Result<Vec<ValidatorSlashEvent>> {
        let validator_address = validator_address.into();

        let mut all_slashes = Vec::new();
        let mut current_page = pagination;
        let mut total_pages: Option<u64> = None;

        loop {
            let request = QueryValidatorSlashesRequest {
                validator_address: validator_address.clone(),
                starting_height,
                ending_height,
                pagination: current_page.clone(),
            };
            let response: tonic::Response<QueryValidatorSlashesResponse> =
                self.inner.clone().validator_slashes(request).await?;
            let response = response.into_inner();
            let slashes = response.slashes;
            all_slashes.extend(slashes);

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

        Ok(all_slashes)
    }

    pub async fn delegation_rewards(
        &self,
        delegator_address: impl Into<String>,
        validator_address: impl Into<String>,
    ) -> Result<Vec<DecCoin>> {
        let delegator_address = delegator_address.into();
        let validator_address = validator_address.into();

        let request = QueryDelegationRewardsRequest {
            delegator_address,
            validator_address,
        };
        let response: ::tonic::Response<QueryDelegationRewardsResponse> =
            self.inner.clone().delegation_rewards(request).await?;

        let rewards = response.into_inner().rewards;

        Ok(rewards)
    }

    pub async fn delegation_total_rewards(
        &self,
        delegator_address: impl Into<String>,
    ) -> Result<Vec<DelegationDelegatorReward>> {
        let delegator_address = delegator_address.into();

        let request = QueryDelegationTotalRewardsRequest { delegator_address };
        let response: ::tonic::Response<QueryDelegationTotalRewardsResponse> =
            self.inner.clone().delegation_total_rewards(request).await?;

        let rewards = response.into_inner().rewards;

        Ok(rewards)
    }

    // TODO: check what the response actually is. convert to Validator or Addr if appropriate.
    pub async fn delegator_validators(
        &self,
        delegator_address: impl Into<String>,
    ) -> Result<Vec<String>> {
        let delegator_address = delegator_address.into();

        let request = QueryDelegatorValidatorsRequest { delegator_address };
        let response: ::tonic::Response<QueryDelegatorValidatorsResponse> =
            self.inner.clone().delegator_validators(request).await?;

        let validators = response.into_inner().validators;

        Ok(validators)
    }

    // TODO: convert response to `Addr` or some other type?
    pub async fn delegator_withdraw_address(
        &self,
        delegator_address: impl Into<String>,
    ) -> Result<String> {
        let delegator_address = delegator_address.into();

        let request = QueryDelegatorWithdrawAddressRequest { delegator_address };
        let response: ::tonic::Response<QueryDelegatorWithdrawAddressResponse> = self
            .inner
            .clone()
            .delegator_withdraw_address(request)
            .await?;

        let withdraw_address = response.into_inner().withdraw_address;

        Ok(withdraw_address)
    }

    pub async fn community_pool(
        &self,
        request: impl tonic::IntoRequest<QueryCommunityPoolRequest>,
    ) -> Result<Vec<DecCoin>> {
        let request = QueryCommunityPoolRequest {};
        let response: ::tonic::Response<QueryCommunityPoolResponse> =
            self.inner.clone().community_pool(request).await?;

        let community_pool = response.into_inner().pool;

        Ok(community_pool)
    }
}
