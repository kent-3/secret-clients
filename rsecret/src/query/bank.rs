use super::{Error, Result};
use secretrs::{clients::BankQueryClient, proto::cosmos::bank::v1beta1::*};
use tonic::codegen::{Body, Bytes, StdError};

#[derive(Debug, Clone)]
pub struct BankQuerier<T> {
    inner: BankQueryClient<T>,
}

#[cfg(not(target_arch = "wasm32"))]
impl BankQuerier<::tonic::transport::Channel> {
    pub fn new(channel: ::tonic::transport::Channel) -> Self {
        let inner = BankQueryClient::new(channel);
        Self { inner }
    }
}

#[cfg(target_arch = "wasm32")]
impl BankQuerier<::tonic_web_wasm_client::Client> {
    pub fn new(client: ::tonic_web_wasm_client::Client) -> Self {
        let auth = BankQueryClient::new(client);
        Self { inner: auth }
    }
}

// TODO - add ability to set headers of the request (especially 'x-cosmos-block-height')

impl<T> BankQuerier<T>
where
    T: tonic::client::GrpcService<tonic::body::BoxBody>,
    T::Error: Into<StdError>,
    T::ResponseBody: Body<Data = Bytes> + Send + 'static,
    <T::ResponseBody as Body>::Error: Into<StdError> + Send,
    T: Clone,
{
    pub async fn balance(
        &self,
        address: impl Into<String>,
        denom: impl Into<String>,
    ) -> Result<QueryBalanceResponse> {
        let address = address.into();
        let denom = denom.into();
        let request = QueryBalanceRequest { address, denom };
        let response: ::tonic::Response<QueryBalanceResponse> =
            self.inner.clone().balance(request).await?;

        Ok(response.into_inner())
    }

    pub async fn all_balances(
        &self,
        request: QueryAllBalancesRequest,
    ) -> Result<QueryAllBalancesResponse> {
        todo!()
    }

    pub async fn spendable_balances(
        &self,
        request: QuerySpendableBalancesRequest,
    ) -> Result<QuerySpendableBalancesResponse> {
        todo!()
    }

    pub async fn total_supply(
        &self,
        request: QueryTotalSupplyRequest,
    ) -> Result<QueryTotalSupplyResponse> {
        todo!()
    }

    pub async fn supply_of(&self, request: QuerySupplyOfRequest) -> Result<QuerySupplyOfResponse> {
        todo!()
    }

    pub async fn params(&self) -> Result<Params> {
        let request = QueryParamsRequest {};
        let response: ::tonic::Response<QueryParamsResponse> =
            self.inner.clone().params(request).await?;

        response.into_inner().params.ok_or("params empty".into())
    }

    pub async fn denom_metadata(
        &self,
        request: QueryDenomMetadataRequest,
    ) -> Result<QueryDenomMetadataResponse> {
        todo!()
    }

    pub async fn denoms_metadata(
        &self,
        request: QueryDenomsMetadataRequest,
    ) -> Result<QueryDenomsMetadataResponse> {
        todo!()
    }

    pub async fn denom_owners(
        &self,
        request: QueryDenomOwnersRequest,
    ) -> Result<QueryDenomOwnersResponse> {
        todo!()
    }
}
