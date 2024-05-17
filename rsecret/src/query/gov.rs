use crate::{Error, Result};
use prost::Message;
pub use secretrs::{
    grpc_clients::GovQueryClient,
    proto::cosmos::{
        base::query::v1beta1::{PageRequest, PageResponse},
        gov::v1beta1::*,
    },
};
use tonic::codegen::{Body, Bytes, StdError};
use tracing::{debug, info, warn};

#[derive(Debug, Clone)]
pub struct GovQuerier<T> {
    inner: GovQueryClient<T>,
}

#[cfg(not(target_arch = "wasm32"))]
impl GovQuerier<::tonic::transport::Channel> {
    pub fn new(channel: ::tonic::transport::Channel) -> Self {
        let inner = GovQueryClient::new(channel);
        Self { inner }
    }
}

#[cfg(target_arch = "wasm32")]
impl GovQuerier<::tonic_web_wasm_client::Client> {
    pub fn new(client: ::tonic_web_wasm_client::Client) -> Self {
        let inner = GovQueryClient::new(client);
        Self { inner }
    }
}

impl<T> GovQuerier<T>
where
    T: tonic::client::GrpcService<tonic::body::BoxBody>,
    T::Error: Into<StdError>,
    T::ResponseBody: Body<Data = Bytes> + Send + 'static,
    <T::ResponseBody as Body>::Error: Into<StdError> + Send,
    T: Clone,
{
}
