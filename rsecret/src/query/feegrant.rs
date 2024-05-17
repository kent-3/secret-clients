use crate::{Error, Result};
use prost::Message;
pub use secretrs::{
    grpc_clients::FeeGrantQueryClient,
    proto::cosmos::{
        base::query::v1beta1::{PageRequest, PageResponse},
        feegrant::v1beta1::*,
    },
};
use tonic::codegen::{Body, Bytes, StdError};
use tracing::{debug, info, warn};

#[derive(Debug, Clone)]
pub struct FeeGrantQuerier<T> {
    inner: FeeGrantQueryClient<T>,
}

#[cfg(not(target_arch = "wasm32"))]
impl FeeGrantQuerier<::tonic::transport::Channel> {
    pub fn new(channel: ::tonic::transport::Channel) -> Self {
        let inner = FeeGrantQueryClient::new(channel);
        Self { inner }
    }
}

#[cfg(target_arch = "wasm32")]
impl FeeGrantQuerier<::tonic_web_wasm_client::Client> {
    pub fn new(client: ::tonic_web_wasm_client::Client) -> Self {
        let inner = FeeGrantQueryClient::new(client);
        Self { inner }
    }
}

impl<T> FeeGrantQuerier<T>
where
    T: tonic::client::GrpcService<tonic::body::BoxBody>,
    T::Error: Into<StdError>,
    T::ResponseBody: Body<Data = Bytes> + Send + 'static,
    <T::ResponseBody as Body>::Error: Into<StdError> + Send,
    T: Clone,
{
}
