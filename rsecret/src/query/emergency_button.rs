use crate::{Error, Result};
use prost::Message;
pub use secretrs::{
    grpc_clients::EmergencyButtonQueryClient,
    proto::{
        cosmos::base::query::v1beta1::{PageRequest, PageResponse},
        secret::emergencybutton::v1beta1::*,
    },
};
use tonic::{
    body::BoxBody,
    client::GrpcService,
    codegen::{Body, Bytes, StdError},
};
use tracing::{debug, info, warn};

#[derive(Debug, Clone)]
pub struct EmergencyButtonQuerier<T> {
    inner: EmergencyButtonQueryClient<T>,
}

#[cfg(not(target_arch = "wasm32"))]
impl EmergencyButtonQuerier<::tonic::transport::Channel> {
    pub fn new(channel: ::tonic::transport::Channel) -> Self {
        let inner = EmergencyButtonQueryClient::new(channel);
        Self { inner }
    }
}

#[cfg(target_arch = "wasm32")]
impl EmergencyButtonQuerier<::tonic_web_wasm_client::Client> {
    pub fn new(client: ::tonic_web_wasm_client::Client) -> Self {
        let inner = EmergencyButtonQueryClient::new(client);
        Self { inner }
    }
}

impl<T> EmergencyButtonQuerier<T>
where
    T: GrpcService<BoxBody> + Clone,
    T::Error: Into<StdError>,
    T::ResponseBody: Body<Data = Bytes> + Send + 'static,
    <T::ResponseBody as Body>::Error: Into<StdError> + Send,
{
    pub async fn params(&self) -> Result<Params> {
        let request = ParamsRequest {};
        let response: ::tonic::Response<ParamsResponse> =
            self.inner.clone().params(request).await?;

        let params = response
            .into_inner()
            .params
            .ok_or(Error::MissingField { name: "params" })?;

        Ok(params)
    }
}
