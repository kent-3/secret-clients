#![allow(unused)]

use crate::{secret_client::CreateQuerierOptions, CreateClientOptions, Error, Result};
use secretrs::utils::encryption::SecretUtils;
use std::sync::Arc;
use tonic::{
    body::BoxBody,
    client::GrpcService,
    codegen::{Body, Bytes, StdError},
};

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
pub mod node; // TODO: module not in cosmos_sdk_proto
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
use evidence::EvidenceQuerier;
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
// use node::NodeQuerier;
use params::ParamsQuerier;
use registration::RegistrationQuerier;
use slashing::SlashingQuerier;
use staking::StakingQuerier;
use tendermint::TendermintQuerier;
use tx::TxQuerier;
use upgrade::UpgradeQuerier;

#[derive(Debug, Clone)]
pub struct Querier<T, U>
where
    T: GrpcService<BoxBody> + Clone,
    T::Error: Into<StdError>,
    T::ResponseBody: Body<Data = Bytes> + Send + 'static,
    <T::ResponseBody as Body>::Error: Into<StdError> + Send,
    U: SecretUtils,
{
    pub auth: AuthQuerier<T>,
    pub authz: AuthzQuerier<T>,
    pub bank: BankQuerier<T>,
    pub compute: ComputeQuerier<T, U>,
    pub distribution: DistributionQuerier<T>,
    pub emergency_button: EmergencyButtonQuerier<T>,
    pub evidence: EvidenceQuerier<T>,
    pub feegrant: FeeGrantQuerier<T>,
    pub gov: GovQuerier<T>,
    pub ibc_channel: IbcChannelQuerier<T>,
    pub ibc_client: IbcClientQuerier<T>,
    pub ibc_connection: IbcConnectionQuerier<T>,
    // pub ibc_fee: IbcFeeQuerier<T>,
    pub ibc_interchain_accounts_controller: IbcInterchainAccountsControllerQuerier<T>,
    pub ibc_interchain_accounts_host: IbcInterchainAccountsHostQuerier<T>,
    // pub ibc_packet_forward: IbcPacketForwardQuerier<T>,
    pub ibc_transfer: IbcTransferQuerier<T>,
    pub mauth: InterTxQuerier<T>,
    pub mint: MintQuerier<T>,
    // pub node: NodeQuerier<T>,
    pub params: ParamsQuerier<T>,
    pub registration: RegistrationQuerier<T>,
    pub slashing: SlashingQuerier<T>,
    pub staking: StakingQuerier<T>,
    pub tendermint: TendermintQuerier<T>,
    pub tx: TxQuerier<T>,
    pub upgrade: UpgradeQuerier<T>,
}

#[derive(Debug, Clone)]
pub struct MiniQuerier<T, U>
where
    T: tonic::client::GrpcService<tonic::body::BoxBody> + Clone + Sync,
    T::Error: Into<StdError>,
    T::ResponseBody: Body<Data = Bytes> + Send + 'static,
    <T::ResponseBody as Body>::Error: Into<StdError> + Send,
    U: SecretUtils + Sync,
{
    pub auth: AuthQuerier<T>,
    pub bank: BankQuerier<T>,
    pub compute: ComputeQuerier<T, U>,
    pub tendermint: TendermintQuerier<T>,
    pub tx: TxQuerier<T>,
}

#[cfg(not(target_arch = "wasm32"))]
impl<U: SecretUtils + Sync> MiniQuerier<::tonic::transport::Channel, U> {
    pub async fn connect(options: CreateQuerierOptions<U>) -> Result<Self> {
        let channel = ::tonic::transport::Channel::from_static(options.url)
            .connect()
            .await?;
        Ok(Self::new(channel, options.enigma_utils))
    }

    pub fn new(channel: ::tonic::transport::Channel, enigma_utils: Arc<U>) -> Self {
        let auth = AuthQuerier::new(channel.clone());
        let bank = BankQuerier::new(channel.clone());
        let compute = ComputeQuerier::new(channel.clone(), enigma_utils);
        let tendermint = TendermintQuerier::new(channel.clone());
        let tx = TxQuerier::new(channel.clone());

        Self {
            auth,
            bank,
            compute,
            tendermint,
            tx,
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl<U: SecretUtils + Sync> Querier<::tonic::transport::Channel, U> {
    pub async fn connect(options: CreateQuerierOptions<U>) -> Result<Self> {
        let channel = ::tonic::transport::Channel::from_static(options.url)
            .connect()
            .await?;
        Ok(Self::new(channel, options.enigma_utils))
    }

    pub fn new(channel: ::tonic::transport::Channel, enigma_utils: Arc<U>) -> Self {
        let auth = AuthQuerier::new(channel.clone());
        let authz = AuthzQuerier::new(channel.clone());
        let bank = BankQuerier::new(channel.clone());
        let compute = ComputeQuerier::new(channel.clone(), enigma_utils);
        let distribution = DistributionQuerier::new(channel.clone());
        let emergency_button = EmergencyButtonQuerier::new(channel.clone());
        let evidence = EvidenceQuerier::new(channel.clone());
        let feegrant = FeeGrantQuerier::new(channel.clone());
        let gov = GovQuerier::new(channel.clone());
        let ibc_channel = IbcChannelQuerier::new(channel.clone());
        let ibc_client = IbcClientQuerier::new(channel.clone());
        let ibc_connection = IbcConnectionQuerier::new(channel.clone());
        let ibc_interchain_accounts_controller =
            IbcInterchainAccountsControllerQuerier::new(channel.clone());
        let ibc_interchain_accounts_host = IbcInterchainAccountsHostQuerier::new(channel.clone());
        let ibc_transfer = IbcTransferQuerier::new(channel.clone());
        let mauth = InterTxQuerier::new(channel.clone());
        let mint = MintQuerier::new(channel.clone());
        let params = ParamsQuerier::new(channel.clone());
        let registration = RegistrationQuerier::new(channel.clone());
        let slashing = SlashingQuerier::new(channel.clone());
        let staking = StakingQuerier::new(channel.clone());
        let tendermint = TendermintQuerier::new(channel.clone());
        let tx = TxQuerier::new(channel.clone());
        let upgrade = UpgradeQuerier::new(channel.clone());

        Self {
            auth,
            authz,
            bank,
            compute,
            distribution,
            emergency_button,
            evidence,
            feegrant,
            gov,
            ibc_channel,
            ibc_client,
            ibc_connection,
            ibc_interchain_accounts_controller,
            ibc_interchain_accounts_host,
            ibc_transfer,
            mauth,
            mint,
            params,
            registration,
            slashing,
            staking,
            tendermint,
            tx,
            upgrade,
        }
    }
}

#[cfg(target_arch = "wasm32")]
impl<U: SecretUtils + Sync> MiniQuerier<::tonic_web_wasm_client::Client, U> {
    pub fn new(client: ::tonic_web_wasm_client::Client, enigma_utils: Arc<U>) -> Self {
        let auth = AuthQuerier::new(client.clone());
        let bank = BankQuerier::new(client.clone());
        let compute = ComputeQuerier::new(client.clone(), enigma_utils);
        let tendermint = TendermintQuerier::new(client.clone());
        let tx = TxQuerier::new(client.clone());

        Self {
            auth,
            bank,
            compute,
            tendermint,
            tx,
        }
    }
}

#[cfg(target_arch = "wasm32")]
impl<U: SecretUtils + Sync> Querier<::tonic_web_wasm_client::Client, U> {
    pub fn new(client: ::tonic_web_wasm_client::Client, enigma_utils: Arc<U>) -> Self {
        let auth = AuthQuerier::new(client.clone());
        let authz = AuthzQuerier::new(client.clone());
        let bank = BankQuerier::new(client.clone());
        let compute = ComputeQuerier::new(client.clone(), enigma_utils);
        let distribution = DistributionQuerier::new(client.clone());
        let emergency_button = EmergencyButtonQuerier::new(client.clone());
        let evidence = EvidenceQuerier::new(client.clone());
        let feegrant = FeeGrantQuerier::new(client.clone());
        let gov = GovQuerier::new(client.clone());
        let ibc_channel = IbcChannelQuerier::new(client.clone());
        let ibc_client = IbcClientQuerier::new(client.clone());
        let ibc_connection = IbcConnectionQuerier::new(client.clone());
        let ibc_interchain_accounts_controller =
            IbcInterchainAccountsControllerQuerier::new(client.clone());
        let ibc_interchain_accounts_host = IbcInterchainAccountsHostQuerier::new(client.clone());
        let ibc_transfer = IbcTransferQuerier::new(client.clone());
        let mauth = InterTxQuerier::new(client.clone());
        let mint = MintQuerier::new(client.clone());
        let params = ParamsQuerier::new(client.clone());
        let registration = RegistrationQuerier::new(client.clone());
        let slashing = SlashingQuerier::new(client.clone());
        let staking = StakingQuerier::new(client.clone());
        let tendermint = TendermintQuerier::new(client.clone());
        let tx = TxQuerier::new(client.clone());
        let upgrade = UpgradeQuerier::new(client.clone());

        Self {
            auth,
            authz,
            bank,
            compute,
            distribution,
            emergency_button,
            evidence,
            feegrant,
            gov,
            ibc_channel,
            ibc_client,
            ibc_connection,
            ibc_interchain_accounts_controller,
            ibc_interchain_accounts_host,
            ibc_transfer,
            mauth,
            mint,
            params,
            registration,
            slashing,
            staking,
            tendermint,
            tx,
            upgrade,
        }
    }
}
