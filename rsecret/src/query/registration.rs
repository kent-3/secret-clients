use super::{Error, Result};
use crate::CreateClientOptions;
pub use secretrs::{
    grpc_clients::RegistrationQueryClient,
    proto::secret::registration::v1beta1::{
        Key, QueryEncryptedSeedRequest, QueryEncryptedSeedResponse,
    },
};
use tonic::{
    body::BoxBody,
    client::GrpcService,
    codegen::{Body, Bytes, StdError},
};

#[derive(Debug, Clone)]
pub struct RegistrationQuerier<T> {
    inner: RegistrationQueryClient<T>,
}

#[cfg(not(target_arch = "wasm32"))]
impl RegistrationQuerier<::tonic::transport::Channel> {
    // pub async fn connect(options: &CreateClientOptions) -> Result<Self> {
    //     let channel = tonic::transport::Channel::from_static(options.url)
    //         .connect()
    //         .await?;
    //     Ok(Self::new(channel))
    // }
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
    T: GrpcService<BoxBody> + Clone,
    T::Error: Into<StdError>,
    T::ResponseBody: Body<Data = Bytes> + Send + 'static,
    <T::ResponseBody as Body>::Error: Into<StdError> + Send,
{
    /// Returns the key used for transactions
    pub async fn tx_key(&self) -> Result<Key> {
        let request = ();
        let response: ::tonic::Response<Key> = self.inner.clone().tx_key(request).await?;

        let key = response.into_inner();
        Ok(key)
    }

    /// Returns the key used for registration
    pub async fn registration_key(&self) -> Result<Key> {
        let request = ();
        let response: ::tonic::Response<Key> = self.inner.clone().registration_key(request).await?;

        let key = response.into_inner();
        Ok(key)
    }

    /// Returns the encrypted seed for a registered node by public key
    pub async fn encrypted_seed(&self, pub_key: Vec<u8>) -> Result<Vec<u8>> {
        let request = QueryEncryptedSeedRequest { pub_key };
        let response: ::tonic::Response<QueryEncryptedSeedResponse> =
            self.inner.clone().encrypted_seed(request).await?;

        let encrypted_seed = response.into_inner().encrypted_seed;
        Ok(encrypted_seed)
    }
}
