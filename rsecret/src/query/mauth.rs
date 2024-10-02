use crate::{Error, Result};
use prost::Message;
pub use secretrs::{
    grpc_clients::InterTxQueryClient,
    proto::cosmos::base::query::v1beta1::{PageRequest, PageResponse},
    proto::secret::intertx::v1beta1::{
        QueryInterchainAccountFromAddressRequest, QueryInterchainAccountFromAddressResponse,
    },
};
use tonic::{
    body::BoxBody,
    client::GrpcService,
    codegen::{Body, Bytes, StdError},
};
use tracing::{debug, info, warn};

#[derive(Debug, Clone)]
pub struct InterTxQuerier<T> {
    inner: InterTxQueryClient<T>,
}

#[cfg(not(target_arch = "wasm32"))]
impl InterTxQuerier<::tonic::transport::Channel> {
    pub fn new(channel: ::tonic::transport::Channel) -> Self {
        let inner = InterTxQueryClient::new(channel);
        Self { inner }
    }
}

#[cfg(target_arch = "wasm32")]
impl InterTxQuerier<::tonic_web_wasm_client::Client> {
    pub fn new(client: ::tonic_web_wasm_client::Client) -> Self {
        let inner = InterTxQueryClient::new(client);
        Self { inner }
    }
}

impl<T> InterTxQuerier<T>
where
    T: GrpcService<BoxBody> + Clone,
    T::Error: Into<StdError>,
    T::ResponseBody: Body<Data = Bytes> + Send + 'static,
    <T::ResponseBody as Body>::Error: Into<StdError> + Send,
{
    /// QueryInterchainAccountFromAddress returns the interchain account for given owner address on a given connection pair
    pub async fn interchain_account_from_address(
        &self,
        owner: impl Into<String>,
        connection_id: impl Into<String>,
    ) -> Result<String> {
        let owner = owner.into();
        let connection_id = connection_id.into();

        let request = QueryInterchainAccountFromAddressRequest {
            owner,
            connection_id,
        };
        let response = self
            .inner
            .clone()
            .interchain_account_from_address(request)
            .await?;

        Ok(response.into_inner().interchain_account_address)
    }
}
