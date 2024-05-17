use crate::{Error, Result};
use prost::Message;
pub use secretrs::{
    grpc_clients::SlashingQueryClient,
    proto::cosmos::{
        base::query::v1beta1::{PageRequest, PageResponse},
        slashing::v1beta1::*,
    },
};
use tonic::codegen::{Body, Bytes, StdError};
use tracing::{debug, info, warn};

#[derive(Debug, Clone)]
pub struct SlashingQuerier<T> {
    inner: SlashingQueryClient<T>,
}

#[cfg(not(target_arch = "wasm32"))]
impl SlashingQuerier<::tonic::transport::Channel> {
    pub fn new(channel: ::tonic::transport::Channel) -> Self {
        let inner = SlashingQueryClient::new(channel);
        Self { inner }
    }
}

#[cfg(target_arch = "wasm32")]
impl SlashingQuerier<::tonic_web_wasm_client::Client> {
    pub fn new(client: ::tonic_web_wasm_client::Client) -> Self {
        let inner = SlashingQueryClient::new(client);
        Self { inner }
    }
}

impl<T> SlashingQuerier<T>
where
    T: tonic::client::GrpcService<tonic::body::BoxBody>,
    T::Error: Into<StdError>,
    T::ResponseBody: Body<Data = Bytes> + Send + 'static,
    <T::ResponseBody as Body>::Error: Into<StdError> + Send,
    T: Clone,
{
}
