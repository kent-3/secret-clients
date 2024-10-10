use crate::{Error, Result};
use prost::Message;
pub use secretrs::{
    grpc_clients::FeeGrantQueryClient,
    proto::cosmos::{
        base::query::v1beta1::{PageRequest, PageResponse},
        feegrant::v1beta1::*,
    },
};
use tonic::{
    body::BoxBody,
    client::GrpcService,
    codegen::{Body, Bytes, StdError},
};
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
    T: GrpcService<BoxBody> + Clone,
    T::Error: Into<StdError>,
    T::ResponseBody: Body<Data = Bytes> + Send + 'static,
    <T::ResponseBody as Body>::Error: Into<StdError> + Send,
{
    pub async fn allowance(
        &self,
        granter: impl Into<String>,
        grantee: impl Into<String>,
    ) -> Result<Grant> {
        let granter = granter.into();
        let grantee = grantee.into();

        let request = QueryAllowanceRequest { grantee, granter };
        let response: ::tonic::Response<QueryAllowanceResponse> =
            self.inner.clone().allowance(request).await?;

        let allowance = response
            .into_inner()
            .allowance
            .ok_or(Error::MissingField { name: "allowance" })?;

        Ok(allowance)
    }

    pub async fn allowances(
        &self,
        grantee: impl Into<String>,
        pagination: Option<PageRequest>,
    ) -> Result<Vec<Grant>> {
        let grantee = grantee.into();

        let mut all_allowances = Vec::new();
        let mut current_page = pagination;
        let mut total_pages: Option<u64> = None;

        loop {
            let request = QueryAllowancesRequest {
                grantee: grantee.clone(),
                pagination: current_page.clone(),
            };
            let response: ::tonic::Response<QueryAllowancesResponse> =
                self.inner.clone().allowances(request).await?;
            let response = response.into_inner();
            let allowances = response.allowances;
            all_allowances.extend(allowances);

            if let Some(page_response) = response.pagination {
                debug!("{:?}", current_page.as_ref().unwrap());
                debug!("{:?}", page_response);
                if total_pages.is_none() && page_response.total > 0 {
                    let total_count = page_response.total;
                    let limit = current_page.as_ref().unwrap().limit;
                    total_pages = Some((total_count + limit - 1) / limit);
                    debug!("Total pages needed: {}", total_pages.unwrap());
                    if total_pages.unwrap() > 10 {
                        warn!("That's a lot of pages!");
                    }
                }
                if page_response.next_key.is_empty() {
                    break;
                } else {
                    current_page = Some(PageRequest {
                        key: page_response.next_key,
                        ..current_page.unwrap_or_default()
                    });
                }
            } else {
                break;
            }
        }

        Ok(all_allowances)
    }

    pub async fn allowances_by_granter(
        &self,
        granter: impl Into<String>,
        pagination: Option<PageRequest>,
    ) -> Result<Vec<Grant>> {
        let granter = granter.into();

        let mut all_allowances = Vec::new();
        let mut current_page = pagination;
        let mut total_pages: Option<u64> = None;

        loop {
            let request = QueryAllowancesByGranterRequest {
                granter: granter.clone(),
                pagination: current_page.clone(),
            };
            let response: ::tonic::Response<QueryAllowancesByGranterResponse> =
                self.inner.clone().allowances_by_granter(request).await?;
            let response = response.into_inner();
            let allowances = response.allowances;
            all_allowances.extend(allowances);

            if let Some(page_response) = response.pagination {
                debug!("{:?}", current_page.as_ref().unwrap());
                debug!("{:?}", page_response);
                if total_pages.is_none() && page_response.total > 0 {
                    let total_count = page_response.total;
                    let limit = current_page.as_ref().unwrap().limit;
                    total_pages = Some((total_count + limit - 1) / limit);
                    debug!("Total pages needed: {}", total_pages.unwrap());
                    if total_pages.unwrap() > 10 {
                        warn!("That's a lot of pages!");
                    }
                }
                if page_response.next_key.is_empty() {
                    break;
                } else {
                    current_page = Some(PageRequest {
                        key: page_response.next_key,
                        ..current_page.unwrap_or_default()
                    });
                }
            } else {
                break;
            }
        }

        Ok(all_allowances)
    }
}
