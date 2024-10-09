use crate::{Error, Result};
use ibc_proto::ibc::core::client::v1::*;
use prost::Message;
pub use secretrs::{
    grpc_clients::IbcClientQueryClient,
    proto::cosmos::base::query::v1beta1::{PageRequest, PageResponse},
};
use tonic::{
    body::BoxBody,
    client::GrpcService,
    codegen::{Body, Bytes, StdError},
};
use tracing::{debug, info, warn};

#[derive(Debug, Clone)]
pub struct IbcClientQuerier<T> {
    inner: IbcClientQueryClient<T>,
}

#[cfg(not(target_arch = "wasm32"))]
impl IbcClientQuerier<::tonic::transport::Channel> {
    pub fn new(channel: ::tonic::transport::Channel) -> Self {
        let inner = IbcClientQueryClient::new(channel);
        Self { inner }
    }
}

#[cfg(target_arch = "wasm32")]
impl IbcClientQuerier<::tonic_web_wasm_client::Client> {
    pub fn new(client: ::tonic_web_wasm_client::Client) -> Self {
        let inner = IbcClientQueryClient::new(client);
        Self { inner }
    }
}

impl<T> IbcClientQuerier<T>
where
    T: GrpcService<BoxBody> + Clone,
    T::Error: Into<StdError>,
    T::ResponseBody: Body<Data = Bytes> + Send + 'static,
    <T::ResponseBody as Body>::Error: Into<StdError> + Send,
{
    /// ClientState queries an IBC light client.
    pub async fn client_state(
        &self,
        request: impl tonic::IntoRequest<QueryClientStateRequest>,
    ) -> Result<QueryClientStateResponse> {
        todo!()
    }

    /// ClientStates queries all the IBC light clients of a chain.
    pub async fn client_states(
        &self,
        request: impl tonic::IntoRequest<QueryClientStatesRequest>,
    ) -> Result<QueryClientStatesResponse> {
        todo!()
    }

    /// ConsensusState queries a consensus state associated with a client state at
    /// a given height.
    pub async fn consensus_state(
        &self,
        request: impl tonic::IntoRequest<QueryConsensusStateRequest>,
    ) -> Result<QueryConsensusStateResponse> {
        todo!()
    }

    /// ConsensusStates queries all the consensus state associated with a given
    /// client.
    pub async fn consensus_states(
        &self,
        request: impl tonic::IntoRequest<QueryConsensusStatesRequest>,
    ) -> Result<QueryConsensusStatesResponse> {
        todo!()
    }

    /// Status queries the status of an IBC client.
    pub async fn client_status(
        &self,
        request: impl tonic::IntoRequest<QueryClientStatusRequest>,
    ) -> Result<QueryClientStatusResponse> {
        todo!()
    }

    /// ClientParams queries all parameters of the ibc client.
    pub async fn client_params(
        &self,
        request: impl tonic::IntoRequest<QueryClientParamsRequest>,
    ) -> Result<QueryClientParamsResponse> {
        todo!()
    }

    /// UpgradedClientState queries an Upgraded IBC light client.
    pub async fn upgraded_client_state(
        &self,
        request: impl tonic::IntoRequest<QueryUpgradedClientStateRequest>,
    ) -> Result<QueryUpgradedClientStateResponse> {
        todo!()
    }

    /// UpgradedConsensusState queries an Upgraded IBC consensus state.
    pub async fn upgraded_consensus_state(
        &self,
        request: impl tonic::IntoRequest<QueryUpgradedConsensusStateRequest>,
    ) -> Result<QueryUpgradedConsensusStateResponse> {
        todo!()
    }
}
