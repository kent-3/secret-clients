use super::{Error, Result};
use crate::{secret_client::CreateQuerierOptions, CreateClientOptions};
use async_trait::async_trait;
use base64::prelude::{Engine as _, BASE64_STANDARD};
use regex::Regex;
use secretrs::utils::encryption::SecretMsg;
use secretrs::{
    grpc_clients::ComputeQueryClient,
    proto::secret::compute::v1beta1::{
        ContractCodeHistoryEntry, ContractInfo, ContractInfoWithAddress, QueryByCodeIdRequest,
        QueryByContractAddressRequest, QueryByLabelRequest, QueryCodeHashResponse,
        QueryCodeResponse, QueryCodesResponse, QueryContractAddressResponse,
        QueryContractHistoryRequest, QueryContractHistoryResponse, QueryContractInfoResponse,
        QueryContractLabelResponse, QueryContractsByCodeIdResponse, QuerySecretContractRequest,
        QuerySecretContractResponse,
    },
    utils::encryption::SecretUtils,
};
use serde::Serialize;
use std::{collections::HashMap, sync::Arc};
use tonic::{
    body::BoxBody,
    client::GrpcService,
    codegen::{Body, Bytes, StdError},
};

#[derive(Debug, Clone)]
pub struct ComputeQuerier<T, U: SecretUtils> {
    inner: ComputeQueryClient<T>,
    enigma_utils: Arc<U>,
    code_hash_cache: HashMap<String, String>,
}

#[cfg(not(target_arch = "wasm32"))]
impl<U: SecretUtils + Sync> ComputeQuerier<::tonic::transport::Channel, U> {
    pub async fn connect(options: CreateQuerierOptions<U>) -> Result<Self> {
        let channel = tonic::transport::Channel::from_static(options.url)
            .connect()
            .await?;
        Ok(Self::new(channel, options.enigma_utils.into()))
    }

    pub fn new(channel: ::tonic::transport::Channel, enigma_utils: Arc<U>) -> Self {
        let inner = ComputeQueryClient::new(channel);
        let enigma_utils = enigma_utils;
        let code_hash_cache = HashMap::new();
        Self {
            inner,
            enigma_utils,
            code_hash_cache,
        }
    }
}

#[cfg(target_arch = "wasm32")]
impl<U: SecretUtils + Sync> ComputeQuerier<::tonic_web_wasm_client::Client, U> {
    pub fn new(client: tonic_web_wasm_client::Client, enigma_utils: Arc<U>) -> Self {
        let inner = ComputeQueryClient::new(client);
        let enigma_utils = enigma_utils.into();
        let code_hash_cache = HashMap::new();
        Self {
            inner,
            enigma_utils,
            code_hash_cache,
        }
    }
}

impl<T, U> ComputeQuerier<T, U>
where
    T: GrpcService<BoxBody> + Clone + Sync,
    T::Error: Into<StdError>,
    T::ResponseBody: Body<Data = Bytes> + Send + 'static,
    <T::ResponseBody as Body>::Error: Into<StdError> + Send,
    U: SecretUtils + Sync,
{
    pub async fn contract_info(
        &self,
        contract_address: impl Into<String>,
    ) -> Result<QueryContractInfoResponse> {
        let contract_address = contract_address.into();
        let request = QueryByContractAddressRequest { contract_address };
        self.inner
            .clone()
            .contract_info(request)
            .await
            .map_err(Into::into)
            .map(::tonic::Response::into_inner)
    }

    pub async fn contracts_by_code_id(
        &self,
        code_id: impl Into<u64>,
    ) -> Result<QueryContractsByCodeIdResponse> {
        let code_id = code_id.into();
        let request = QueryByCodeIdRequest { code_id };
        self.inner
            .clone()
            .contracts_by_code_id(request)
            .await
            .map_err(Into::into)
            .map(::tonic::Response::into_inner)
    }

    pub async fn code(&self, code_id: impl Into<u64>) -> Result<QueryCodeResponse> {
        let code_id = code_id.into();
        let request = QueryByCodeIdRequest { code_id };
        self.inner
            .clone()
            .code(request)
            .await
            .map_err(Into::into)
            .map(::tonic::Response::into_inner)
    }

    pub async fn codes(&self) -> Result<QueryCodesResponse> {
        let request = ();
        self.inner
            .clone()
            .codes(request)
            .await
            .map_err(Into::into)
            .map(::tonic::Response::into_inner)
    }

    pub async fn code_hash_by_contract_address(
        &self,
        contract_address: impl Into<String>,
    ) -> Result<String> {
        let contract_address = contract_address.into();
        let request = QueryByContractAddressRequest { contract_address };
        self.inner
            .clone()
            .code_hash_by_contract_address(request)
            .await
            .map_err(Into::into)
            .map(::tonic::Response::into_inner)
            .map(|resp| resp.code_hash)
    }

    pub async fn code_hash_by_code_id(&self, code_id: impl Into<u64>) -> Result<String> {
        let code_id = code_id.into();
        let request = QueryByCodeIdRequest { code_id };
        self.inner
            .clone()
            .code_hash_by_code_id(request)
            .await
            .map_err(Into::into)
            .map(::tonic::Response::into_inner)
            .map(|resp| resp.code_hash)
    }

    pub async fn label_by_address(&self, contract_address: impl Into<String>) -> Result<String> {
        let contract_address = contract_address.into();
        let request = QueryByContractAddressRequest { contract_address };
        self.inner
            .clone()
            .label_by_address(request)
            .await
            .map_err(Into::into)
            .map(::tonic::Response::into_inner)
            .map(|resp| resp.label)
    }

    pub async fn address_by_label(&self, label: impl Into<String>) -> Result<String> {
        let label = label.into();
        let request = QueryByLabelRequest { label };
        self.inner
            .clone()
            .address_by_label(request)
            .await
            .map_err(Into::into)
            .map(::tonic::Response::into_inner)
            .map(|resp| resp.contract_address)
    }

    pub async fn contract_history(
        &self,
        contract_address: impl Into<String>,
    ) -> Result<QueryContractHistoryResponse> {
        let contract_address = contract_address.into();
        let request = QueryContractHistoryRequest { contract_address };
        self.inner
            .clone()
            .contract_history(request)
            .await
            .map_err(Into::into)
            .map(::tonic::Response::into_inner)
    }

    // TODO: make it possible to call without code_hash? by computing it from contract_address
    // and saving it in the code_hash_cache.

    /// Returns a JSON string of the query response.
    pub async fn query_secret_contract<M: Serialize + Send + Sync>(
        &self,
        contract_address: impl Into<String>,
        code_hash: impl Into<String>,
        query: M,
    ) -> Result<String> {
        let contract_address = contract_address.into();
        let code_hash = code_hash.into();

        let encrypted = self.enigma_utils.encrypt(&code_hash, &query).await?;
        let encrypted = SecretMsg::from(encrypted);
        let nonce = encrypted.nonce();
        let query = encrypted.into_inner();

        let mut compute = self.inner.clone();

        let req = QuerySecretContractRequest {
            contract_address,
            query,
        };

        // TODO: needs work...
        // should we return the metadata (x-cosmos-block-height) with the data?
        let response = match compute.query_secret_contract(req).await {
            Ok(response) => {
                let (metadata, response, _extensions) = response.into_parts();
                let decrypted_bytes = self.enigma_utils.decrypt(&nonce, &response.data).await?;
                let decrypted_b64_string = String::from_utf8(decrypted_bytes)?;
                let decoded_bytes = BASE64_STANDARD.decode(decrypted_b64_string)?;
                let data = String::from_utf8(decoded_bytes)?;

                // let http_headers = metadata.into_headers();
                // let block_height = http_headers
                //     .get("x-cosmos-block-height")
                //     .ok_or("Missing header")?
                //     .to_str()?;

                // the data is usually padded with spaces
                Ok(data.trim().to_string())
            }
            Err(status) => {
                let error_message = status.message();

                let re = Regex::new(r"encrypted: (.*?):").unwrap();

                if let Some(caps) = re.captures(error_message) {
                    let encrypted_bytes = BASE64_STANDARD.decode(&caps[1])?;
                    let decrypted_bytes =
                        self.enigma_utils.decrypt(&nonce, &encrypted_bytes).await?;
                    let decrypted_string = String::from_utf8(decrypted_bytes)?;
                    Err(decrypted_string)
                } else {
                    Err(error_message.to_string())
                }
            }
        };

        response.map_err(Into::into)
    }
}

// not sure what I am doing...

#[async_trait]
pub trait Querier {
    type Response;
    type Request;

    async fn perform(&self, request: Self::Request) -> Result<Self::Response>;
}

pub trait Encryptor {
    fn encrypt(&self, code_hash: impl Into<String>, query: &[u8]) -> Result<SecretMsg>;
    fn decrypt(&self, nonce: &[u8; 32], ciphertext: &[u8]) -> Result<Vec<u8>>;
}

#[async_trait]
pub trait Compute: Querier + Encryptor {
    async fn query_secret_contract(
        &self,
        request: QuerySecretContractRequest,
        code_hash: impl Into<String>,
    ) -> Result<QuerySecretContractResponse>;
}
