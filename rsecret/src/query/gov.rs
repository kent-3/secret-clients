use crate::{Error, Result};
use prost::Message;
pub use secretrs::{
    grpc_clients::GovQueryClient,
    proto::cosmos::{
        base::query::v1beta1::{PageRequest, PageResponse},
        gov::v1beta1::*,
    },
};
use tonic::{
    body::BoxBody,
    client::GrpcService,
    codegen::{Body, Bytes, StdError},
};
use tracing::{debug, info, warn};

#[derive(Debug, Clone)]
pub struct GovQuerier<T> {
    inner: GovQueryClient<T>,
}

#[cfg(not(target_arch = "wasm32"))]
impl GovQuerier<::tonic::transport::Channel> {
    pub fn new(channel: ::tonic::transport::Channel) -> Self {
        let inner = GovQueryClient::new(channel);
        Self { inner }
    }
}

#[cfg(target_arch = "wasm32")]
impl GovQuerier<::tonic_web_wasm_client::Client> {
    pub fn new(client: ::tonic_web_wasm_client::Client) -> Self {
        let inner = GovQueryClient::new(client);
        Self { inner }
    }
}

impl<T> GovQuerier<T>
where
    T: GrpcService<BoxBody> + Clone,
    T::Error: Into<StdError>,
    T::ResponseBody: Body<Data = Bytes> + Send + 'static,
    <T::ResponseBody as Body>::Error: Into<StdError> + Send,
{
    pub async fn proposal(&self, proposal_id: u64) -> Result<Proposal> {
        let request = QueryProposalRequest { proposal_id };
        let response: ::tonic::Response<QueryProposalResponse> =
            self.inner.clone().proposal(request).await?;

        let proposal = response
            .into_inner()
            .proposal
            .ok_or(Error::MissingField { name: "proposal" })?;

        Ok(proposal)
    }

    pub async fn proposals(
        &self,
        proposal_status: i32,
        voter: impl Into<String>,
        depositor: impl Into<String>,
        pagination: Option<PageRequest>,
    ) -> Result<Vec<Proposal>> {
        let voter = voter.into();
        let depositor = depositor.into();

        let mut all_proposals = Vec::new();
        let mut current_page = pagination;
        let mut total_pages: Option<u64> = None;

        loop {
            let request = QueryProposalsRequest {
                proposal_status,
                voter: voter.clone(),
                depositor: depositor.clone(),
                pagination: current_page.clone(),
            };
            let response: tonic::Response<QueryProposalsResponse> =
                self.inner.clone().proposals(request).await?;
            let response = response.into_inner();
            let proposals = response.proposals;
            all_proposals.extend(proposals);

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

        Ok(all_proposals)
    }

    pub async fn vote(&self, proposal_id: u64, voter: impl Into<String>) -> Result<Vote> {
        let voter = voter.into();

        let request = QueryVoteRequest { proposal_id, voter };
        let response: ::tonic::Response<QueryVoteResponse> =
            self.inner.clone().vote(request).await?;

        let vote = response
            .into_inner()
            .vote
            .ok_or(Error::MissingField { name: "vote" })?;

        Ok(vote)
    }

    pub async fn votes(
        &self,
        proposal_id: u64,
        pagination: Option<PageRequest>,
    ) -> Result<Vec<Vote>> {
        let mut all_votes = Vec::new();
        let mut current_page = pagination;
        let mut total_pages: Option<u64> = None;

        loop {
            let request = QueryVotesRequest {
                proposal_id,
                pagination: current_page.clone(),
            };
            let response: tonic::Response<QueryVotesResponse> =
                self.inner.clone().votes(request).await?;
            let response = response.into_inner();
            let votes = response.votes;
            all_votes.extend(votes);

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

        Ok(all_votes)
    }

    /// params_type defines which parameters to query for, can be one of "voting",
    /// "tallying" or "deposit".
    pub async fn params(&self, params_type: impl Into<String>) -> Result<Params> {
        let params_type = params_type.into();

        let request = QueryParamsRequest {
            params_type: params_type.clone(),
        };
        let response: ::tonic::Response<QueryParamsResponse> =
            self.inner.clone().params(request).await?;

        match params_type.as_str() {
            "voting" => {
                let params = response
                    .into_inner()
                    .voting_params
                    .ok_or(Error::MissingField {
                        name: "voting_params",
                    })?;

                Ok(Params::VotingParams(params))
            }
            "deposit" => {
                let params = response
                    .into_inner()
                    .deposit_params
                    .ok_or(Error::MissingField {
                        name: "deposit_params",
                    })?;

                Ok(Params::DepositParams(params))
            }
            "tally" => {
                let params = response
                    .into_inner()
                    .tally_params
                    .ok_or(Error::MissingField {
                        name: "tally_params",
                    })?;

                Ok(Params::TallyParams(params))
            }
            _ => Err(Error::custom("Invalid params_type")),
        }
    }

    pub async fn deposit(&self, proposal_id: u64, depositor: impl Into<String>) -> Result<Deposit> {
        let depositor = depositor.into();

        let request = QueryDepositRequest {
            proposal_id,
            depositor,
        };
        let response: ::tonic::Response<QueryDepositResponse> =
            self.inner.clone().deposit(request).await?;

        let deposit = response
            .into_inner()
            .deposit
            .ok_or(Error::MissingField { name: "deposit" })?;

        Ok(deposit)
    }

    pub async fn deposits(
        &self,
        proposal_id: u64,
        pagination: Option<PageRequest>,
    ) -> Result<Vec<Deposit>> {
        let mut all_deposits = Vec::new();
        let mut current_page = pagination;
        let mut total_pages: Option<u64> = None;

        loop {
            let request = QueryDepositsRequest {
                proposal_id,
                pagination: current_page.clone(),
            };
            let response: tonic::Response<QueryDepositsResponse> =
                self.inner.clone().deposits(request).await?;
            let response = response.into_inner();
            let deposits = response.deposits;
            all_deposits.extend(deposits);

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

        Ok(all_deposits)
    }

    pub async fn tally_result(&self, proposal_id: u64) -> Result<TallyResult> {
        let request = QueryTallyResultRequest { proposal_id };
        let response: ::tonic::Response<QueryTallyResultResponse> =
            self.inner.clone().tally_result(request).await?;

        let tally_result = response
            .into_inner()
            .tally
            .ok_or(Error::MissingField { name: "tally" })?;

        Ok(tally_result)
    }
}

#[derive(Debug)]
pub enum Params {
    VotingParams(::secretrs::proto::cosmos::gov::v1beta1::VotingParams),
    DepositParams(::secretrs::proto::cosmos::gov::v1beta1::DepositParams),
    TallyParams(::secretrs::proto::cosmos::gov::v1beta1::TallyParams),
}
