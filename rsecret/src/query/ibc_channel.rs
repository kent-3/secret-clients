use crate::{Error, Result};
use prost::Message;
pub use secretrs::{
    grpc_clients::IbcChannelQueryClient,
    proto::cosmos::base::query::v1beta1::{PageRequest, PageResponse},
    proto::ibc::core::channel::v1::*,
};
use tonic::codegen::{Body, Bytes, StdError};
use tracing::{debug, info, warn};

#[derive(Debug, Clone)]
pub struct IbcChannelQuerier<T> {
    inner: IbcChannelQueryClient<T>,
}

#[cfg(not(target_arch = "wasm32"))]
impl IbcChannelQuerier<::tonic::transport::Channel> {
    pub fn new(channel: ::tonic::transport::Channel) -> Self {
        let inner = IbcChannelQueryClient::new(channel);
        Self { inner }
    }
}

#[cfg(target_arch = "wasm32")]
impl IbcChannelQuerier<::tonic_web_wasm_client::Client> {
    pub fn new(client: ::tonic_web_wasm_client::Client) -> Self {
        let inner = IbcChannelQueryClient::new(client);
        Self { inner }
    }
}

impl<T> IbcChannelQuerier<T>
where
    T: tonic::client::GrpcService<tonic::body::BoxBody>,
    T::Error: Into<StdError>,
    T::ResponseBody: Body<Data = Bytes> + Send + 'static,
    <T::ResponseBody as Body>::Error: Into<StdError> + Send,
    T: Clone,
{
}
