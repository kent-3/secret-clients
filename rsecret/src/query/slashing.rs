use crate::{Error, Result};
use prost::Message;
pub use secretrs::{
    grpc_clients::SlashingQueryClient,
    proto::cosmos::{
        base::query::v1beta1::{PageRequest, PageResponse},
        slashing::v1beta1::*,
    },
};
use tonic::{
    body::BoxBody,
    client::GrpcService,
    codegen::{Body, Bytes, StdError},
};
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
    T: GrpcService<BoxBody> + Clone,
    T::Error: Into<StdError>,
    T::ResponseBody: Body<Data = Bytes> + Send + 'static,
    <T::ResponseBody as Body>::Error: Into<StdError> + Send,
{
    pub async fn params(&self) -> Result<Params> {
        let request = QueryParamsRequest {};
        let response: ::tonic::Response<QueryParamsResponse> =
            self.inner.clone().params(request).await?;

        let params = response
            .into_inner()
            .params
            .ok_or(Error::MissingField { name: "params" })?;

        Ok(params)
    }

    pub async fn signing_info(
        &self,
        cons_address: impl Into<String>,
    ) -> Result<ValidatorSigningInfo> {
        let cons_address = cons_address.into();

        let request = QuerySigningInfoRequest { cons_address };
        let response: ::tonic::Response<QuerySigningInfoResponse> =
            self.inner.clone().signing_info(request).await?;

        let val_signing_info =
            response
                .into_inner()
                .val_signing_info
                .ok_or(Error::MissingField {
                    name: "val_signing_info",
                })?;

        Ok(val_signing_info)
    }

    pub async fn signing_infos(
        &self,
        pagination: Option<PageRequest>,
    ) -> Result<Vec<ValidatorSigningInfo>> {
        let mut all_info = Vec::new();
        let mut current_page = pagination;
        let mut total_pages: Option<u64> = None;

        loop {
            let request = QuerySigningInfosRequest {
                pagination: current_page.clone(),
            };
            let response: tonic::Response<QuerySigningInfosResponse> =
                self.inner.clone().signing_infos(request).await?;
            let response = response.into_inner();
            let info = response.info;
            all_info.extend(info);

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

        Ok(all_info)
    }
}
