#![allow(unused)]

mod authz;
mod bank;
mod compute;
mod crisis;
mod distribution;
mod evidence;
mod feegrant;
mod gov;
mod slashing;
mod staking;

pub use authz::AuthzServiceClient;
pub use bank::BankServiceClient;
pub use compute::ComputeServiceClient;
pub use crisis::CrisisServiceClient;
pub use distribution::DistributionServiceClient;
pub use evidence::EvidenceServiceClient;
pub use feegrant::FeegrantServiceClient;
pub use gov::GovServiceClient;
pub use slashing::SlashingServiceClient;
pub use staking::StakingServiceClient;

use super::{Error, Result};
use crate::{CreateClientOptions, TxOptions};
use secretrs::clients::TxServiceClient;
use secretrs::proto::cosmos::tx::v1beta1::{BroadcastTxRequest, BroadcastTxResponse};
use tonic::codegen::{Body, Bytes, StdError};

#[derive(Debug, Clone)]
pub struct TxSender<T>
where
    T: tonic::client::GrpcService<tonic::body::BoxBody>,
    T::Error: Into<StdError>,
    T::ResponseBody: Body<Data = Bytes> + Send + 'static,
    <T::ResponseBody as Body>::Error: Into<StdError> + Send,
    T: Clone,
{
    pub authz: AuthzServiceClient<T>,
    pub bank: BankServiceClient<T>,
    pub compute: ComputeServiceClient<T>,
    pub crisis: CrisisServiceClient<T>,
    pub distribution: DistributionServiceClient<T>,
    pub evidence: EvidenceServiceClient<T>,
    pub feegrant: FeegrantServiceClient<T>,
    pub gov: GovServiceClient<T>,
    pub slashing: SlashingServiceClient<T>,
    pub staking: StakingServiceClient<T>,
    tx: TxServiceClient<T>,
}

#[cfg(not(target_arch = "wasm32"))]
impl TxSender<::tonic::transport::Channel> {
    pub async fn connect(options: &CreateClientOptions) -> Result<Self> {
        let channel = tonic::transport::Channel::from_static(options.url)
            .connect()
            .await?;
        Ok(Self::new(channel, options))
    }

    pub fn new(channel: ::tonic::transport::Channel, options: &CreateClientOptions) -> Self {
        let authz = AuthzServiceClient::new(channel.clone());
        let bank = BankServiceClient::new(channel.clone());
        let compute = ComputeServiceClient::new(channel.clone(), options);
        let crisis = CrisisServiceClient::new(channel.clone());
        let distribution = DistributionServiceClient::new(channel.clone());
        let evidence = EvidenceServiceClient::new(channel.clone());
        let feegrant = FeegrantServiceClient::new(channel.clone());
        let gov = GovServiceClient::new(channel.clone());
        let slashing = SlashingServiceClient::new(channel.clone());
        let staking = StakingServiceClient::new(channel.clone());
        let tx = TxServiceClient::new(channel.clone());

        Self {
            authz,
            bank,
            compute,
            crisis,
            distribution,
            evidence,
            feegrant,
            gov,
            slashing,
            staking,
            tx,
        }
    }
}

#[cfg(target_arch = "wasm32")]
impl TxSender<::tonic_web_wasm_client::Client> {
    pub fn new(client: ::tonic_web_wasm_clien::Client) -> Self {
        let bank = BankServiceClient::new(client.clone());
        let compute = ComputeServiceClient::new(client.clone());
        let tx = TxServiceClient::new(client.clone());
        Self { bank, compute, tx }
    }
}

impl<T> TxSender<T>
where
    T: tonic::client::GrpcService<tonic::body::BoxBody>,
    T::Error: Into<StdError>,
    T::ResponseBody: Body<Data = Bytes> + Send + 'static,
    <T::ResponseBody as Body>::Error: Into<StdError> + Send,
    T: Clone,
{
    // TODO - figure out how to support multiple messages
    pub async fn broadcast(&mut self, request: BroadcastTxRequest) -> Result<BroadcastTxResponse> {
        self.tx
            .broadcast_tx(request)
            .await
            .map_err(Into::into)
            .map(::tonic::Response::into_inner)
    }
}
