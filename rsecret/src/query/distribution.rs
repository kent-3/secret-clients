use crate::{Error, Result};
use prost::Message;
pub use secretrs::{
    grpc_clients::DistributionQueryClient,
    proto::cosmos::{
        base::query::v1beta1::{PageRequest, PageResponse},
        distribution::v1beta1::*,
    },
};
use tonic::codegen::{Body, Bytes, StdError};
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
    T: tonic::client::GrpcService<tonic::body::BoxBody>,
    T::Error: Into<StdError>,
    T::ResponseBody: Body<Data = Bytes> + Send + 'static,
    <T::ResponseBody as Body>::Error: Into<StdError> + Send,
    T: Clone,
{
}
