use super::{Error, Result};
use crate::CreateClientOptions;
use secretrs::{
    grpc_clients::RegistrationQueryClient,
    proto::secret::registration::v1beta1::{QueryEncryptedSeedRequest, QueryEncryptedSeedResponse},
};
use tonic::codegen::{Body, Bytes, StdError};

#[derive(Debug, Clone)]
pub struct RegistrationQuerier<T> {
    inner: RegistrationQueryClient<T>,
}

#[cfg(not(target_arch = "wasm32"))]
impl RegistrationQuerier<::tonic::transport::Channel> {
    pub async fn connect(options: &CreateClientOptions) -> Result<Self> {
        let channel = tonic::transport::Channel::from_static(options.url)
            .connect()
            .await?;
        Ok(Self::new(channel))
    }
    pub fn new(channel: ::tonic::transport::Channel) -> Self {
        let inner = RegistrationQueryClient::new(channel);
        Self { inner }
    }
}

#[cfg(target_arch = "wasm32")]
impl RegistrationQuerier<::tonic_web_wasm_client::Client> {
    pub fn new(client: ::tonic_web_wasm_client::Client) -> Self {
        let inner = RegistrationQueryClient::new(client);
        Self { inner }
    }
}

impl<T> RegistrationQuerier<T>
where
    T: tonic::client::GrpcService<tonic::body::BoxBody>,
    T::Error: Into<StdError>,
    T::ResponseBody: Body<Data = Bytes> + Send + 'static,
    <T::ResponseBody as Body>::Error: Into<StdError> + Send,
    T: Clone,
{
    // TODO:
}
