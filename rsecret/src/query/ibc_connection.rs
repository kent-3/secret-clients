use crate::{Error, Result};
use prost::Message;
pub use secretrs::{
    grpc_clients::IbcConnectionQueryClient,
    proto::cosmos::base::query::v1beta1::{PageRequest, PageResponse},
    proto::ibc::core::connection::v1::*,
};
use tonic::codegen::{Body, Bytes, StdError};
use tracing::{debug, info, warn};

#[derive(Debug, Clone)]
pub struct IbcConnectionQuerier<T> {
    inner: IbcConnectionQueryClient<T>,
}

#[cfg(not(target_arch = "wasm32"))]
impl IbcConnectionQuerier<::tonic::transport::Channel> {
    pub fn new(channel: ::tonic::transport::Channel) -> Self {
        let inner = IbcConnectionQueryClient::new(channel);
        Self { inner }
    }
}

#[cfg(target_arch = "wasm32")]
impl IbcConnectionQuerier<::tonic_web_wasm_client::Client> {
    pub fn new(client: ::tonic_web_wasm_client::Client) -> Self {
        let inner = IbcConnectionQueryClient::new(client);
        Self { inner }
    }
}

impl<T> IbcConnectionQuerier<T>
where
    T: tonic::client::GrpcService<tonic::body::BoxBody>,
    T::Error: Into<StdError>,
    T::ResponseBody: Body<Data = Bytes> + Send + 'static,
    <T::ResponseBody as Body>::Error: Into<StdError> + Send,
    T: Clone,
{
    /// Connection queries an IBC connection end.
    pub async fn connection(
        &mut self,
        request: impl tonic::IntoRequest<QueryConnectionRequest>,
    ) -> Result<QueryConnectionResponse> {
        todo!()
    }

    /// Connections queries all the IBC connections of a chain.
    pub async fn connections(
        &mut self,
        request: impl tonic::IntoRequest<QueryConnectionsRequest>,
    ) -> Result<QueryConnectionsResponse> {
        todo!()
    }
    /// ClientConnections queries the connection paths associated with a client
    /// state.
    pub async fn client_connections(
        &mut self,
        request: impl tonic::IntoRequest<QueryClientConnectionsRequest>,
    ) -> Result<QueryClientConnectionsResponse> {
        todo!()
    }
    /// ConnectionClientState queries the client state associated with the
    /// connection.
    pub async fn connection_client_state(
        &mut self,
        request: impl tonic::IntoRequest<QueryConnectionClientStateRequest>,
    ) -> Result<QueryConnectionClientStateResponse> {
        todo!()
    }
    /// ConnectionConsensusState queries the consensus state associated with the
    /// connection.
    pub async fn connection_consensus_state(
        &mut self,
        request: impl tonic::IntoRequest<QueryConnectionConsensusStateRequest>,
    ) -> Result<QueryConnectionConsensusStateResponse> {
        todo!()
    }
}
