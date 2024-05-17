use crate::{Error, Result};
use prost::Message;
pub use secretrs::{
    grpc_clients::EvidenceQueryClient,
    proto::cosmos::{
        base::query::v1beta1::{PageRequest, PageResponse},
        evidence::v1beta1::*,
    },
};
use tonic::codegen::{Body, Bytes, StdError};
use tracing::{debug, info, warn};

#[derive(Debug, Clone)]
pub struct EvidenceQuerier<T> {
    inner: EvidenceQueryClient<T>,
}

#[cfg(not(target_arch = "wasm32"))]
impl EvidenceQuerier<::tonic::transport::Channel> {
    pub fn new(channel: ::tonic::transport::Channel) -> Self {
        let inner = EvidenceQueryClient::new(channel);
        Self { inner }
    }
}

#[cfg(target_arch = "wasm32")]
impl EvidenceQuerier<::tonic_web_wasm_client::Client> {
    pub fn new(client: ::tonic_web_wasm_client::Client) -> Self {
        let inner = EvidenceQueryClient::new(client);
        Self { inner }
    }
}

impl<T> EvidenceQuerier<T>
where
    T: tonic::client::GrpcService<tonic::body::BoxBody>,
    T::Error: Into<StdError>,
    T::ResponseBody: Body<Data = Bytes> + Send + 'static,
    <T::ResponseBody as Body>::Error: Into<StdError> + Send,
    T: Clone,
{
}
