use super::{Error, Result};
use crate::CreateClientOptions;
use secretrs::{
    grpc_clients::StakingQueryClient,
    proto::cosmos::staking::v1beta1::{
        QueryDelegationRequest, QueryDelegationResponse, QueryDelegatorDelegationsRequest,
        QueryDelegatorDelegationsResponse, QueryDelegatorUnbondingDelegationsRequest,
        QueryDelegatorUnbondingDelegationsResponse, QueryDelegatorValidatorRequest,
        QueryDelegatorValidatorResponse, QueryDelegatorValidatorsRequest,
        QueryDelegatorValidatorsResponse, QueryHistoricalInfoRequest, QueryHistoricalInfoResponse,
        QueryParamsRequest, QueryParamsResponse, QueryPoolRequest, QueryPoolResponse,
        QueryRedelegationsRequest, QueryRedelegationsResponse, QueryUnbondingDelegationRequest,
        QueryUnbondingDelegationResponse, QueryValidatorDelegationsRequest,
        QueryValidatorDelegationsResponse, QueryValidatorRequest, QueryValidatorResponse,
        QueryValidatorUnbondingDelegationsRequest, QueryValidatorUnbondingDelegationsResponse,
        QueryValidatorsRequest, QueryValidatorsResponse,
    },
};
use tonic::codegen::{Body, Bytes, StdError};

#[derive(Debug, Clone)]
pub struct StakingQuerier<T> {
    inner: StakingQueryClient<T>,
}

#[cfg(not(target_arch = "wasm32"))]
impl StakingQuerier<::tonic::transport::Channel> {
    pub async fn connect(options: &CreateClientOptions) -> Result<Self> {
        let channel = tonic::transport::Channel::from_static(options.url)
            .connect()
            .await?;
        Ok(Self::new(channel))
    }
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
    T: tonic::client::GrpcService<tonic::body::BoxBody>,
    T::Error: Into<StdError>,
    T::ResponseBody: Body<Data = Bytes> + Send + 'static,
    <T::ResponseBody as Body>::Error: Into<StdError> + Send,
    T: Clone,
{
    // TODO:
}
