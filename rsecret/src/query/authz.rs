use super::{Error, Result};
use prost::Message;
pub use secretrs::{
    grpc_clients::AuthzQueryClient,
    proto::cosmos::{
        authz::v1beta1::{
            GenericAuthorization, GenesisState, Grant, GrantAuthorization,
            QueryGranteeGrantsRequest, QueryGranteeGrantsResponse, QueryGranterGrantsRequest,
            QueryGranterGrantsResponse, QueryGrantsRequest, QueryGrantsResponse,
        },
        base::query::v1beta1::{PageRequest, PageResponse},
    },
};
use tonic::{
    body::BoxBody,
    client::GrpcService,
    codegen::{Body, Bytes, StdError},
};
use tracing::{debug, info, warn};

#[derive(Debug, Clone)]
pub struct AuthzQuerier<T> {
    inner: AuthzQueryClient<T>,
}

#[cfg(not(target_arch = "wasm32"))]
impl AuthzQuerier<::tonic::transport::Channel> {
    pub fn new(channel: ::tonic::transport::Channel) -> Self {
        let inner = AuthzQueryClient::new(channel);
        Self { inner }
    }
}

#[cfg(target_arch = "wasm32")]
impl AuthzQuerier<::tonic_web_wasm_client::Client> {
    pub fn new(client: ::tonic_web_wasm_client::Client) -> Self {
        let inner = AuthzQueryClient::new(client);
        Self { inner }
    }
}

impl<T> AuthzQuerier<T>
where
    T: GrpcService<BoxBody> + Clone,
    T::Error: Into<StdError>,
    T::ResponseBody: Body<Data = Bytes> + Send + 'static,
    <T::ResponseBody as Body>::Error: Into<StdError> + Send,
{
    pub async fn grants(
        &self,
        granter: impl Into<String>,
        grantee: impl Into<String>,
        msg_type_url: impl Into<String>,
        pagination: Option<PageRequest>,
    ) -> Result<Vec<Grant>> {
        let granter = granter.into();
        let grantee = grantee.into();
        let msg_type_url = msg_type_url.into();

        // let request = QueryGrantsRequest {
        //     granter,
        //     grantee,
        //     msg_type_url,
        //     pagination,
        // };
        // let response: ::tonic::Response<QueryGrantsResponse> =
        //     self.inner.clone().grants(request).await?;
        //
        // Ok(response.into_inner().grants)

        let mut all_grants = Vec::new();
        let mut current_page = pagination;
        let mut total_pages: Option<u64> = None;

        loop {
            let request = QueryGrantsRequest {
                granter: granter.clone(),
                grantee: grantee.clone(),
                msg_type_url: msg_type_url.clone(),
                pagination: current_page.clone(),
            };
            let response = self.inner.clone().grants(request).await?;
            let response = response.into_inner();
            let grants = response.grants;
            all_grants.extend(grants);

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

        Ok(all_grants)
    }

    pub async fn granter_grants(
        &self,
        granter: impl Into<String>,
        pagination: Option<PageRequest>,
    ) -> Result<Vec<GrantAuthorization>> {
        let granter = granter.into();

        // let request = QueryGranterGrantsRequest {
        //     granter,
        //     pagination,
        // };
        // let response: ::tonic::Response<QueryGranterGrantsResponse> =
        //     self.inner.clone().granter_grants(request).await?;
        //
        // Ok(response.into_inner().grants)

        let mut all_grants = Vec::new();
        let mut current_page = pagination;
        let mut total_pages: Option<u64> = None;

        loop {
            let request = QueryGranterGrantsRequest {
                granter: granter.clone(),
                pagination: current_page.clone(),
            };
            let response = self.inner.clone().granter_grants(request).await?;
            let response = response.into_inner();
            let grants = response.grants;
            all_grants.extend(grants);

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

        Ok(all_grants)
    }

    // TODO: pagination
    pub async fn grantee_grants(
        &self,
        grantee: impl Into<String>,
        pagination: Option<PageRequest>,
    ) -> Result<QueryGranteeGrantsResponse> {
        let grantee = grantee.into();

        let request = QueryGranteeGrantsRequest {
            grantee,
            pagination,
        };
        let response: ::tonic::Response<QueryGranteeGrantsResponse> =
            self.inner.clone().grantee_grants(request).await?;

        Ok(response.into_inner())
    }
}
