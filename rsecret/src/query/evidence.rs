use crate::{Error, Result};
use prost::Message;
use secretrs::Any;
pub use secretrs::{
    grpc_clients::EvidenceQueryClient,
    proto::cosmos::{
        base::query::v1beta1::{PageRequest, PageResponse},
        evidence::v1beta1::*,
    },
};
use tonic::{
    body::BoxBody,
    client::GrpcService,
    codegen::{Body, Bytes, StdError},
};
use tracing::{debug, info, warn};

#[derive(Debug, Clone)]
pub struct EvidenceQuerier<T> {
    inner: EvidenceQueryClient<T>,
}

#[cfg(not(target_arch = "wasm32"))]
impl EvidenceQuerier<::tonic::transport::Channel> {
    pub fn new(channel: ::tonic::transport::Channel) -> Self {
        let inner = EvidenceQueryClient::new(channel);
        Self { inner }
    }
}

#[cfg(target_arch = "wasm32")]
impl EvidenceQuerier<::tonic_web_wasm_client::Client> {
    pub fn new(client: ::tonic_web_wasm_client::Client) -> Self {
        let inner = EvidenceQueryClient::new(client);
        Self { inner }
    }
}

impl<T> EvidenceQuerier<T>
where
    T: GrpcService<BoxBody> + Clone,
    T::Error: Into<StdError>,
    T::ResponseBody: Body<Data = Bytes> + Send + 'static,
    <T::ResponseBody as Body>::Error: Into<StdError> + Send,
{
    // TODO: decode the Any into the appropriate type/types
    pub async fn evidence(&self, evidence_hash: impl Into<Vec<u8>>) -> Result<Any> {
        let evidence_hash = evidence_hash.into();
        // TODO: use hash instead of evidence_hash? (check what Secret uses)
        let hash = String::new();

        let request = QueryEvidenceRequest {
            evidence_hash,
            hash,
        };
        let response: ::tonic::Response<QueryEvidenceResponse> =
            self.inner.clone().evidence(request).await?;

        let evidence = response
            .into_inner()
            .evidence
            .ok_or(Error::MissingField { name: "evidence" })?;

        Ok(evidence)
    }

    // TODO: decode the Any into the appropriate type/types
    pub async fn all_evidence(&self, pagination: Option<PageRequest>) -> Result<Vec<Any>> {
        let mut all_evidence = Vec::new();
        let mut current_page = pagination;
        let mut total_pages: Option<u64> = None;

        loop {
            let request = QueryAllEvidenceRequest {
                pagination: current_page.clone(),
            };
            let response: tonic::Response<QueryAllEvidenceResponse> =
                self.inner.clone().all_evidence(request).await?;
            let response = response.into_inner();
            let evidence = response.evidence;
            all_evidence.extend(evidence);

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

        Ok(all_evidence)
    }
}
