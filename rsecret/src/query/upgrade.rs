use crate::{Error, Result};
use prost::Message;
pub use secretrs::{
    grpc_clients::UpgradeQueryClient,
    proto::cosmos::{
        base::query::v1beta1::{PageRequest, PageResponse},
        upgrade::v1beta1::*,
    },
};
use tonic::{
    body::BoxBody,
    client::GrpcService,
    codegen::{Body, Bytes, StdError},
};
use tracing::{debug, info, warn};

#[derive(Debug, Clone)]
pub struct UpgradeQuerier<T> {
    inner: UpgradeQueryClient<T>,
}

#[cfg(not(target_arch = "wasm32"))]
impl UpgradeQuerier<::tonic::transport::Channel> {
    pub fn new(channel: ::tonic::transport::Channel) -> Self {
        let inner = UpgradeQueryClient::new(channel);
        Self { inner }
    }
}

#[cfg(target_arch = "wasm32")]
impl UpgradeQuerier<::tonic_web_wasm_client::Client> {
    pub fn new(client: ::tonic_web_wasm_client::Client) -> Self {
        let inner = UpgradeQueryClient::new(client);
        Self { inner }
    }
}

impl<T> UpgradeQuerier<T>
where
    T: GrpcService<BoxBody> + Clone,
    T::Error: Into<StdError>,
    T::ResponseBody: Body<Data = Bytes> + Send + 'static,
    <T::ResponseBody as Body>::Error: Into<StdError> + Send,
{
    pub async fn current_plan(&self) -> Result<Plan> {
        let request = QueryCurrentPlanRequest {};
        let response: ::tonic::Response<QueryCurrentPlanResponse> =
            self.inner.clone().current_plan(request).await?;

        let plan = response
            .into_inner()
            .plan
            .ok_or(Error::MissingField { name: "plan" })?;

        Ok(plan)
    }

    // TODO: maybe return a block `Height` instead?
    pub async fn applied_plan(&self, name: impl Into<String>) -> Result<i64> {
        let name = name.into();

        let request = QueryAppliedPlanRequest { name };
        let response: ::tonic::Response<QueryAppliedPlanResponse> =
            self.inner.clone().applied_plan(request).await?;

        let height = response.into_inner().height;

        Ok(height)
    }

    // TODO: how do we make sense of the Vec<u8> in the response?
    pub async fn upgraded_consensus_state(
        &self,
        last_height: impl Into<i64>,
        request: impl tonic::IntoRequest<QueryUpgradedConsensusStateRequest>,
    ) -> Result<Vec<u8>> {
        let last_height = last_height.into();

        let request = QueryUpgradedConsensusStateRequest { last_height };
        let response: ::tonic::Response<QueryUpgradedConsensusStateResponse> =
            self.inner.clone().upgraded_consensus_state(request).await?;

        let upgraded_consensus_state = response.into_inner().upgraded_consensus_state;

        Ok(upgraded_consensus_state)
    }

    pub async fn module_versions(
        &self,
        module_name: impl Into<String>,
    ) -> Result<Vec<ModuleVersion>> {
        let module_name = module_name.into();

        let request = QueryModuleVersionsRequest { module_name };
        let response: ::tonic::Response<QueryModuleVersionsResponse> =
            self.inner.clone().module_versions(request).await?;

        let module_versions = response.into_inner().module_versions;

        Ok(module_versions)
    }

    /// Since: cosmos-sdk 0.46
    pub async fn authority(
        &self,
        request: impl tonic::IntoRequest<QueryAuthorityRequest>,
    ) -> Result<QueryAuthorityResponse> {
        unimplemented!()
    }
}
