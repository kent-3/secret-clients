use std::collections::HashMap;

use super::{Error, Result};
use crate::CreateClientOptions;
use secretrs::{
    clients::ComputeQueryClient,
    proto::secret::compute::v1beta1::{
        ContractCodeHistoryEntry, ContractInfo, ContractInfoWithAddress, QueryByCodeIdRequest,
        QueryByContractAddressRequest, QueryByLabelRequest, QueryCodeHashResponse,
        QueryCodeResponse, QueryCodesResponse, QueryContractAddressResponse,
        QueryContractHistoryRequest, QueryContractHistoryResponse, QueryContractInfoResponse,
        QueryContractLabelResponse, QueryContractsByCodeIdResponse, QuerySecretContractRequest,
        QuerySecretContractResponse,
    },
    utils::encryption::SecretMsg,
    EncryptionUtils,
};

use base64::prelude::{Engine as _, BASE64_STANDARD};
use regex::Regex;
use tonic::{
    async_trait,
    codegen::{Body, Bytes, StdError},
};

#[derive(Debug, Clone)]
pub struct ComputeQuerier<T> {
    inner: ComputeQueryClient<T>,
    encryption_utils: EncryptionUtils,
    code_hash_cache: HashMap<&'static str, String>,
}

#[cfg(not(target_arch = "wasm32"))]
impl ComputeQuerier<::tonic::transport::Channel> {
    pub async fn connect(options: &CreateClientOptions) -> Result<Self> {
        let channel = tonic::transport::Channel::from_static(options.url)
            .connect()
            .await?;
        Ok(Self::new(channel, options))
    }
    pub fn new(channel: ::tonic::transport::Channel, options: &CreateClientOptions) -> Self {
        let inner = ComputeQueryClient::new(channel);
        let encryption_utils = EncryptionUtils::new(options.encryption_seed, options.chain_id)
            .expect("failed to create EncryptionUtils");
        let code_hash_cache = HashMap::new();
        Self {
            inner,
            encryption_utils,
            code_hash_cache,
        }
    }
}

#[cfg(target_arch = "wasm32")]
impl ComputeQuerier<::tonic_web_wasm_client::Client> {
    pub fn new(client: ::tonic_web_wasm_client::Client) -> Self {
        let auth = ComputeQueryClient::new(client);
        Self { inner: auth }
    }
}

impl<T> ComputeQuerier<T>
where
    T: tonic::client::GrpcService<tonic::body::BoxBody>,
    T::Error: Into<StdError>,
    T::ResponseBody: Body<Data = Bytes> + Send + 'static,
    <T::ResponseBody as Body>::Error: Into<StdError> + Send,
    T: Clone,
{
    pub async fn contract_info(&self, contract_address: impl Into<String>) -> Result<ContractInfo> {
        let contract_address = contract_address.into();
        let request = QueryByContractAddressRequest { contract_address };
        let response: QueryContractInfoResponse = todo!();
    }

    pub async fn contracts_by_code_id(
        &self,
        code_id: impl Into<u64>,
    ) -> Result<Vec<ContractInfoWithAddress>> {
        let code_id = code_id.into();
        let request = QueryByCodeIdRequest { code_id };
        let response: QueryContractsByCodeIdResponse = todo!();

        Ok(response.contract_infos)
    }

    pub async fn code(&self, code_id: impl Into<u64>) -> Result<QueryCodeResponse> {
        let code_id = code_id.into();
        let request = QueryByCodeIdRequest { code_id };
        let response: QueryCodeResponse = todo!();

        Ok(response)
    }

    pub async fn codes(&self) -> Result<QueryCodesResponse> {
        let request = ();
        let response: QueryCodesResponse = todo!();

        Ok(response)
    }

    pub async fn code_hash_by_contract_address(
        &self,
        contract_address: impl Into<String>,
    ) -> Result<String> {
        let contract_address = contract_address.into();
        let request = QueryByContractAddressRequest { contract_address };
        let response: QueryCodeHashResponse = todo!();

        Ok(response.code_hash)
    }

    pub async fn code_hash_by_code_id(&self, code_id: impl Into<u64>) -> Result<String> {
        let code_id = code_id.into();
        let request = QueryByCodeIdRequest { code_id };
        let response: QueryCodeHashResponse = todo!();

        Ok(response.code_hash)
    }

    pub async fn label_by_address(&self, contract_address: impl Into<String>) -> Result<String> {
        let contract_address = contract_address.into();
        let request = QueryByContractAddressRequest { contract_address };
        let response: QueryContractLabelResponse = todo!();

        Ok(response.label)
    }

    pub async fn address_by_label(&self, label: impl Into<String>) -> Result<String> {
        let label = label.into();
        let request = QueryByLabelRequest { label };
        let response: QueryContractAddressResponse = todo!();

        Ok(response.contract_address)
    }

    pub async fn contract_history(
        &self,
        contract_address: impl Into<String>,
    ) -> Result<Vec<ContractCodeHistoryEntry>> {
        let contract_address = contract_address.into();
        let request = QueryContractHistoryRequest { contract_address };
        let response: QueryContractHistoryResponse = todo!();

        Ok(response.entries)
    }

    pub async fn query_secret_contract(
        &self,
        request: QuerySecretContractRequest,
        // TODO - make it possible to call without code_hash? by computing it from contract_address
        // and saving it in the code_hash_cache.
        code_hash: impl Into<String>,
    ) -> Result<(String, String)> {
        let code_hash = code_hash.into();
        let query = &request.query;

        // TODO - read the chain_id from somewhere
        let encrypted = self.encryption_utils.encrypt(&code_hash, &query)?;
        let nonce = encrypted.nonce();
        let query = encrypted.into_inner();

        let mut compute = self.inner.clone();

        let req = QuerySecretContractRequest { query, ..request };

        // TODO - needs work...
        // should we return the metadata (x-cosmos-block-height) with the data?
        let response = match compute.query_secret_contract(req).await {
            Ok(response) => {
                let (metadata, response, _extensions) = response.into_parts();
                let decrypted_bytes = self.encryption_utils.decrypt(&nonce, &response.data)?;
                let decrypted_b64_string = String::from_utf8(decrypted_bytes)?;
                let decoded_bytes = BASE64_STANDARD.decode(decrypted_b64_string)?;
                let data = String::from_utf8(decoded_bytes)?;

                let http_headers = metadata.into_headers();
                let block_height = http_headers
                    .get("x-cosmos-block-height")
                    .ok_or("Missing header")?
                    .to_str()?;

                Ok((data, block_height.to_owned()))
            }
            Err(status) => {
                let error_message = status.message();

                let re = Regex::new(r"encrypted: (.*?):").unwrap();

                if let Some(caps) = re.captures(error_message) {
                    let encrypted_bytes = BASE64_STANDARD.decode(&caps[1])?;
                    let decrypted_bytes =
                        self.encryption_utils.decrypt(&nonce, &encrypted_bytes)?;
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
