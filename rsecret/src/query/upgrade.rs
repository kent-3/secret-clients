use crate::{Error, Result};
use prost::Message;
pub use secretrs::{
    grpc_clients::UpgradeQueryClient,
    proto::cosmos::{
        base::query::v1beta1::{PageRequest, PageResponse},
        upgrade::v1beta1::*,
    },
};
use tonic::codegen::{Body, Bytes, StdError};
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
    T: tonic::client::GrpcService<tonic::body::BoxBody>,
    T::Error: Into<StdError>,
    T::ResponseBody: Body<Data = Bytes> + Send + 'static,
    <T::ResponseBody as Body>::Error: Into<StdError> + Send,
    T: Clone,
{
}
