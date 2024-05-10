#![allow(unused)]

use crate::CreateClientOptions;

pub mod auth;
pub mod bank;
pub mod compute;
pub mod registration;
pub mod staking;
pub mod tendermint;
pub mod tx;

use auth::AuthQuerier;
use bank::BankQuerier;
use compute::ComputeQuerier;
use tendermint::TendermintQuerier;
use tx::TxQuerier;

use super::{Error, Result};
use tonic::codegen::{Body, Bytes, StdError};

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
        let tendermint = TendermintQuerier::new(channel.clone());
        let tx = TxQuerier::new(channel.clone());
        //etc

        Self {
            auth,
            bank,
            compute,
            tendermint,
            tx,
        }
    }
}
