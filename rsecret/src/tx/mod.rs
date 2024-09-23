#![allow(unused)]

// TODO:
pub mod authz;
pub mod bank;
pub mod compute;
pub mod crisis;
pub mod distribution;
pub mod emergency_button;
pub mod evidence;
pub mod feegrant;
pub mod gov;
pub mod ibc_channel;
pub mod ibc_client;
pub mod ibc_connection;
pub mod ibc_fee;
pub mod ibc_transfer;
pub mod registration;
pub mod slashing;
pub mod staking;
pub mod vesting;

pub use authz::AuthzServiceClient;
pub use bank::BankServiceClient;
pub use compute::ComputeServiceClient;
pub use crisis::CrisisServiceClient;
pub use distribution::DistributionServiceClient;
pub use evidence::EvidenceServiceClient;
pub use feegrant::FeegrantServiceClient;
pub use gov::GovServiceClient;
use secretrs::proto::cosmos::tx::v1beta1::{SimulateRequest, SimulateResponse};
pub use slashing::SlashingServiceClient;
pub use staking::StakingServiceClient;

use super::{Error, Result};
use crate::secret_network_client::CreateTxSenderOptions;
use crate::wallet::{AminoSigner, DirectSigner, Signer};
use crate::{CreateClientOptions, TxOptions};
pub use secretrs::grpc_clients::TxServiceClient;
pub use secretrs::proto::cosmos::tx::v1beta1::{BroadcastTxRequest, BroadcastTxResponse};
use tonic::codegen::{Body, Bytes, StdError};

#[derive(Debug)]
pub struct TxSender<T, S>
where
    T: tonic::client::GrpcService<tonic::body::BoxBody>,
    T::Error: Into<StdError>,
    T::ResponseBody: Body<Data = Bytes> + Send + 'static,
    <T::ResponseBody as Body>::Error: Into<StdError> + Send,
    T: Clone,
    S: Signer,
    <S as AminoSigner>::Error: std::error::Error + Send + Sync + 'static,
    <S as DirectSigner>::Error: std::error::Error + Send + Sync + 'static,
{
    pub authz: AuthzServiceClient<T>,
    pub bank: BankServiceClient<T>,
    pub compute: ComputeServiceClient<T, S>,
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
impl<S> TxSender<::tonic::transport::Channel, S>
where
    S: Signer,
    <S as AminoSigner>::Error: std::error::Error + Send + Sync,
    <S as DirectSigner>::Error: std::error::Error + Send + Sync,
{
    pub async fn connect(options: CreateTxSenderOptions<S>) -> Result<Self> {
        let channel = tonic::transport::Channel::from_static(options.url)
            .connect()
            .await?;
        Ok(Self::new(channel, options))
    }

    pub fn new(channel: ::tonic::transport::Channel, options: CreateTxSenderOptions<S>) -> Self {
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
    pub fn new(client: ::tonic_web_wasm_client::Client, options: CreateTxSenderOptions) -> Self {
        let authz = AuthzServiceClient::new(client.clone());
        let bank = BankServiceClient::new(client.clone());
        let compute = ComputeServiceClient::new(client.clone(), options);
        let crisis = CrisisServiceClient::new(client.clone());
        let distribution = DistributionServiceClient::new(client.clone());
        let evidence = EvidenceServiceClient::new(client.clone());
        let feegrant = FeegrantServiceClient::new(client.clone());
        let gov = GovServiceClient::new(client.clone());
        let slashing = SlashingServiceClient::new(client.clone());
        let staking = StakingServiceClient::new(client.clone());
        let tx = TxServiceClient::new(client.clone());

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

impl<T, S> TxSender<T, S>
where
    T: tonic::client::GrpcService<tonic::body::BoxBody>,
    T::Error: Into<StdError>,
    T::ResponseBody: Body<Data = Bytes> + Send + 'static,
    <T::ResponseBody as Body>::Error: Into<StdError> + Send,
    T: Clone,
    S: Signer,
    <S as AminoSigner>::Error: std::error::Error + Send + Sync,
    <S as DirectSigner>::Error: std::error::Error + Send + Sync,
{
    // TODO - figure out how to support multiple messages
    pub async fn broadcast(&self, request: BroadcastTxRequest) -> Result<BroadcastTxResponse> {
        self.tx
            .clone()
            .broadcast_tx(request)
            .await
            .map_err(Error::from)
            .map(::tonic::Response::into_inner)
    }

    pub async fn simulate(&self, request: SimulateRequest) -> Result<SimulateResponse> {
        self.tx
            .clone()
            .simulate(request)
            .await
            .map_err(Error::from)
            .map(::tonic::Response::into_inner)
    }
}
