// use secretrs::grpc_clients::TxServiceClient;
// use tonic::codegen::{Body, Bytes, StdError};

macro_rules! impl_as_ref_for_service_client {
    ($client:ty) => {
        impl<T> AsRef<TxServiceClient<T>> for $client
        where
            T: tonic::client::GrpcService<tonic::body::BoxBody>,
            T::Error: Into<tonic::codegen::StdError>,
            T::ResponseBody: tonic::codegen::Body<Data = tonic::codegen::Bytes> + Send + 'static,
            <T::ResponseBody as tonic::codegen::Body>::Error: Into<tonic::codegen::StdError> + Send,
            T: Clone,
        {
            fn as_ref(&self) -> &TxServiceClient<T> {
                &self.inner
            }
        }
    };
}

pub(crate) use impl_as_ref_for_service_client;
