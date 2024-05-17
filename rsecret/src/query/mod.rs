#![allow(unused)]

use crate::CreateClientOptions;
use crate::{Error, Result};
use tonic::codegen::{Body, Bytes, StdError};

pub mod auth;
pub mod authz;
pub mod bank;
pub mod compute;
pub mod distribution;
pub mod emergency_button;
pub mod evidence; // TODO: decode `Any` types
pub mod feegrant;
pub mod gov;
pub mod ibc_channel; // TODO:
pub mod ibc_client; // TODO:
pub mod ibc_connection; // TODO:
pub mod ibc_fee; // TODO: module not in cosmos_sdk_proto
pub mod ibc_interchain_accounts_controller;
pub mod ibc_interchain_accounts_host;
pub mod ibc_packet_forward; // TODO: module not in cosmos_sdk_proto
pub mod ibc_transfer;
pub mod mauth;
pub mod mint;
pub mod node;
pub mod params;
pub mod registration;
pub mod slashing;
pub mod staking;
pub mod tendermint;
pub mod tx;
pub mod upgrade;

use auth::AuthQuerier;
use authz::AuthzQuerier;
use bank::BankQuerier;
use compute::ComputeQuerier;
use distribution::DistributionQuerier;
use emergency_button::EmergencyButtonQuerier;
use feegrant::FeeGrantQuerier;
use gov::GovQuerier;
use ibc_channel::IbcChannelQuerier;
use ibc_client::IbcClientQuerier;
use ibc_connection::IbcConnectionQuerier;
// use ibc_fee::IbcFeeQuerier;
use ibc_interchain_accounts_controller::IbcInterchainAccountsControllerQuerier;
use ibc_interchain_accounts_host::IbcInterchainAccountsHostQuerier;
// use ibc_packet_forward::IbcPacketForwardQuerier;
use ibc_transfer::IbcTransferQuerier;
use mauth::InterTxQuerier;
use mint::MintQuerier;
use params::ParamsQuerier;
use registration::RegistrationQuerier;
use slashing::SlashingQuerier;
use staking::StakingQuerier;
use tendermint::TendermintQuerier;
use tx::TxQuerier;
use upgrade::UpgradeQuerier;

#[derive(Debug, Clone)]
pub struct Querier<T>
where
    T: tonic::client::GrpcService<tonic::body::BoxBody>,
    T::Error: Into<StdError>,
    T::ResponseBody: Body<Data = Bytes> + Send + 'static,
    <T::ResponseBody as Body>::Error: Into<StdError> + Send,
    T: Clone,
{
    pub auth: AuthQuerier<T>,
    pub authz: AuthzQuerier<T>,
    pub bank: BankQuerier<T>,
    pub compute: ComputeQuerier<T>,
    pub registration: RegistrationQuerier<T>,
    pub staking: StakingQuerier<T>,
    pub tendermint: TendermintQuerier<T>,
    pub tx: TxQuerier<T>,
}

#[cfg(not(target_arch = "wasm32"))]
impl Querier<::tonic::transport::Channel> {
    pub async fn connect(options: &CreateClientOptions) -> Result<Self> {
        let channel = ::tonic::transport::Channel::from_static(options.url)
            .connect()
            .await?;
        Ok(Self::new(channel, options))
    }

    pub fn new(channel: ::tonic::transport::Channel, options: &CreateClientOptions) -> Self {
        let auth = AuthQuerier::new(channel.clone());
        let authz = AuthzQuerier::new(channel.clone());
        let bank = BankQuerier::new(channel.clone());
        let compute = ComputeQuerier::new(channel.clone(), &options);
        let registration = RegistrationQuerier::new(channel.clone());
        let staking = StakingQuerier::new(channel.clone());
        let tendermint = TendermintQuerier::new(channel.clone());
        let tx = TxQuerier::new(channel.clone());
        //etc

        Self {
            auth,
            authz,
            bank,
            compute,
            registration,
            staking,
            tendermint,
            tx,
        }
    }
}

#[cfg(target_arch = "wasm32")]
impl Querier<::tonic_web_wasm_client::Client> {
    pub fn new(client: ::tonic_web_wasm_client::Client, options: &CreateClientOptions) -> Self {
        let auth = AuthQuerier::new(client.clone());
        let bank = BankQuerier::new(client.clone());
        let compute = ComputeQuerier::new(client.clone(), &options);
        let registration = RegistrationQuerier::new(client.clone());
        let staking = StakingQuerier::new(client.clone());
        let tendermint = TendermintQuerier::new(client.clone());
        let tx = TxQuerier::new(client.clone());
        //etc

        Self {
            auth,
            bank,
            compute,
            registration,
            staking,
            tendermint,
            tx,
        }
    }
}
