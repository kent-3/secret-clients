use crate::{Error, Result};
use prost::Message;
pub use secretrs::{
    grpc_clients::ParamsQueryClient,
    proto::cosmos::{
        base::query::v1beta1::{PageRequest, PageResponse},
        params::v1beta1::*,
    },
};
use tonic::codegen::{Body, Bytes, StdError};
use tracing::{debug, info, warn};

#[derive(Debug, Clone)]
pub struct ParamsQuerier<T> {
    inner: ParamsQueryClient<T>,
}

#[cfg(not(target_arch = "wasm32"))]
impl ParamsQuerier<::tonic::transport::Channel> {
    pub fn new(channel: ::tonic::transport::Channel) -> Self {
        let inner = ParamsQueryClient::new(channel);
        Self { inner }
    }
}

#[cfg(target_arch = "wasm32")]
impl ParamsQuerier<::tonic_web_wasm_client::Client> {
    pub fn new(client: ::tonic_web_wasm_client::Client) -> Self {
        let inner = ParamsQueryClient::new(client);
        Self { inner }
    }
}

impl<T> ParamsQuerier<T>
where
    T: tonic::client::GrpcService<tonic::body::BoxBody>,
    T::Error: Into<StdError>,
    T::ResponseBody: Body<Data = Bytes> + Send + 'static,
    <T::ResponseBody as Body>::Error: Into<StdError> + Send,
    T: Clone,
{
}
