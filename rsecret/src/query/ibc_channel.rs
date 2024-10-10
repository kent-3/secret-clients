use crate::{Error, Result};
use ibc_proto::ibc::core::channel::v1::*;
use prost::Message;
pub use secretrs::{
    grpc_clients::IbcChannelQueryClient,
    proto::cosmos::base::query::v1beta1::{PageRequest, PageResponse},
};
use tonic::{
    body::BoxBody,
    client::GrpcService,
    codegen::{Body, Bytes, StdError},
};
use tracing::{debug, info, warn};

#[derive(Debug, Clone)]
pub struct IbcChannelQuerier<T> {
    inner: IbcChannelQueryClient<T>,
}

#[cfg(not(target_arch = "wasm32"))]
impl IbcChannelQuerier<::tonic::transport::Channel> {
    pub fn new(channel: ::tonic::transport::Channel) -> Self {
        let inner = IbcChannelQueryClient::new(channel);
        Self { inner }
    }
}

#[cfg(target_arch = "wasm32")]
impl IbcChannelQuerier<::tonic_web_wasm_client::Client> {
    pub fn new(client: ::tonic_web_wasm_client::Client) -> Self {
        let inner = IbcChannelQueryClient::new(client);
        Self { inner }
    }
}

impl<T> IbcChannelQuerier<T>
where
    T: GrpcService<BoxBody> + Clone,
    T::Error: Into<StdError>,
    T::ResponseBody: Body<Data = Bytes> + Send + 'static,
    <T::ResponseBody as Body>::Error: Into<StdError> + Send,
{
    /// Channel queries an IBC Channel.
    pub async fn channel(
        &self,
        request: impl tonic::IntoRequest<QueryChannelRequest>,
    ) -> Result<QueryChannelResponse> {
        todo!()
    }

    /// Channels queries all the IBC channels of a chain.
    pub async fn channels(
        &self,
        request: impl tonic::IntoRequest<QueryChannelsRequest>,
    ) -> Result<QueryChannelsResponse> {
        todo!()
    }

    /// ConnectionChannels queries all the channels associated with a connection
    /// end.
    pub async fn connection_channels(
        &self,
        request: impl tonic::IntoRequest<QueryConnectionChannelsRequest>,
    ) -> Result<QueryConnectionChannelsResponse> {
        todo!()
    }

    /// ChannelClientState queries for the client state for the channel associated
    /// with the provided channel identifiers.
    pub async fn channel_client_state(
        &self,
        request: impl tonic::IntoRequest<QueryChannelClientStateRequest>,
    ) -> Result<QueryChannelClientStateResponse> {
        todo!()
    }

    /// ChannelConsensusState queries for the consensus state for the channel
    /// associated with the provided channel identifiers.
    pub async fn channel_consensus_state(
        &self,
        request: impl tonic::IntoRequest<QueryChannelConsensusStateRequest>,
    ) -> Result<QueryChannelConsensusStateResponse> {
        todo!()
    }

    /// PacketCommitment queries a stored packet commitment hash.
    pub async fn packet_commitment(
        &self,
        request: impl tonic::IntoRequest<QueryPacketCommitmentRequest>,
    ) -> Result<QueryPacketCommitmentResponse> {
        todo!()
    }

    /// PacketCommitments returns all the packet commitments hashes associated
    /// with a channel.
    pub async fn packet_commitments(
        &self,
        request: impl tonic::IntoRequest<QueryPacketCommitmentsRequest>,
    ) -> Result<QueryPacketCommitmentsResponse> {
        todo!()
    }

    /// PacketReceipt queries if a given packet sequence has been received on the
    /// queried chain
    pub async fn packet_receipt(
        &self,
        request: impl tonic::IntoRequest<QueryPacketReceiptRequest>,
    ) -> Result<QueryPacketReceiptResponse> {
        todo!()
    }

    /// PacketAcknowledgement queries a stored packet acknowledgement hash.
    pub async fn packet_acknowledgement(
        &self,
        request: impl tonic::IntoRequest<QueryPacketAcknowledgementRequest>,
    ) -> Result<QueryPacketAcknowledgementResponse> {
        todo!()
    }

    /// PacketAcknowledgements returns all the packet acknowledgements associated
    /// with a channel.
    pub async fn packet_acknowledgements(
        &self,
        request: impl tonic::IntoRequest<QueryPacketAcknowledgementsRequest>,
    ) -> Result<QueryPacketAcknowledgementsResponse> {
        todo!()
    }

    /// UnreceivedPackets returns all the unreceived IBC packets associated with a
    /// channel and sequences.
    pub async fn unreceived_packets(
        &self,
        request: impl tonic::IntoRequest<QueryUnreceivedPacketsRequest>,
    ) -> Result<QueryUnreceivedPacketsResponse> {
        todo!()
    }

    /// UnreceivedAcks returns all the unreceived IBC acknowledgements associated
    /// with a channel and sequences.
    pub async fn unreceived_acks(
        &self,
        request: impl tonic::IntoRequest<QueryUnreceivedAcksRequest>,
    ) -> Result<QueryUnreceivedAcksResponse> {
        todo!()
    }

    /// NextSequenceReceive returns the next receive sequence for a given channel.
    pub async fn next_sequence_receive(
        &self,
        request: impl tonic::IntoRequest<QueryNextSequenceReceiveRequest>,
    ) -> Result<QueryNextSequenceReceiveResponse> {
        todo!()
    }
}
