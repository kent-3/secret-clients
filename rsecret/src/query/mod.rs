#![allow(unused)]

use super::{Error, Result};
use crate::CreateClientOptions;
use tonic::codegen::{Body, Bytes, StdError};

pub mod auth;
pub mod bank;
pub mod compute;
pub mod registration;
pub mod staking;
pub mod tendermint;
pub mod tx;

// TODO:
pub mod authz;
pub mod distribution;
pub mod emergency_button;
pub mod evidence;
pub mod feegrant;
pub mod gov;
pub mod ibc_channel;
pub mod ibc_client;
pub mod ibc_connection;
pub mod ibc_fee;
pub mod ibc_interchain_accounts_controller;
pub mod ibc_interchain_accounts_host;
pub mod ibc_packet_forward;
pub mod ibc_transfer;
pub mod node;
pub mod params;
pub mod slashing;
pub mod upgrade;

use auth::AuthQuerier;
use bank::BankQuerier;
use compute::ComputeQuerier;
use registration::RegistrationQuerier;
use staking::StakingQuerier;
use tendermint::TendermintQuerier;
use tx::TxQuerier;

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
        let bank = BankQuerier::new(channel.clone());
        let compute = ComputeQuerier::new(channel.clone(), &options);
        let registration = RegistrationQuerier::new(channel.clone());
        let staking = StakingQuerier::new(channel.clone());
        let tendermint = TendermintQuerier::new(channel.clone());
        let tx = TxQuerier::new(channel.clone());
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
