#![allow(unused)]

// IDEA - Follow secretjs pattern, having a ComputeQuerier struct with private code_hash_cache
// that is a HashMap<String,String>. Whenever a request is made without code hash, compute and
// store it in the cache. (this could exist higher up... see next idea)
//
// IDEA - Try to not have the secret contract query handle all the encryption internally here.
// Encrypt the message ahead of time, and do all the parsing and decryption higher up.
//
// IDEA - The secret proto definitions generate a query_client that has everything pre-defined...
// Is there a way to use that instead?

use std::collections::HashMap;

use ::cosmrs::proto::cosmos::base::query::v1beta1::PageRequest;
use ::cosmrs::Any;

use ::secretrs::proto::secret::compute::v1beta1::query_client::QueryClient as ComputeQueryClient;
use ::secretrs::proto::secret::compute::v1beta1::*;

use super::{try_decode_any, try_decode_response};
use crate::{Error, Result};

#[cfg(not(target_arch = "wasm32"))]
pub struct ComputeQuerier {
    code_hash_cache: HashMap<String, String>,
    pub inner: ComputeQueryClient<::tonic::transport::Channel>,
}

#[cfg(not(target_arch = "wasm32"))]
impl ComputeQuerier {
    pub async fn new(url: impl Into<String>) -> Result<Self> {
        let url = url.into();

        let code_hash_cache = HashMap::new();
        let inner = query_client::QueryClient::connect(url).await.unwrap();

        Ok(Self {
            code_hash_cache,
            inner,
        })
    }
}

#[cfg(target_arch = "wasm32")]
pub struct ComputeQuerier {
    code_hash_cache: HashMap<String, String>,
    pub inner: ComputeQueryClient<::tonic_web_wasm_client::Client>,
}

#[cfg(target_arch = "wasm32")]
impl ComputeQuerier {
    pub async fn new(base_url: impl Into<String>) -> Result<Self> {
        let base_url = base_url.into();
        let web_wasm_client = ::tonic_web_wasm_client::Client::new(base_url);
        let inner = query_client::QueryClient::new(web_wasm_client);

        Ok(Self {
            code_hash_cache: HashMap::new(),
            inner,
        })
    }
}

impl ComputeQuerier {
    pub async fn code_hash_by_contract_address(
        &mut self,
        contract_address: impl Into<String>,
    ) -> Result<QueryCodeHashResponse> {
        let contract_address = contract_address.into();
        let msg = QueryByContractAddressRequest { contract_address };
        let response = self.inner.code_hash_by_contract_address(msg).await.unwrap();

        Ok(response.into_inner())
    }

    pub async fn code_hash_by_code_id(
        &mut self,
        code_id: impl Into<u64>,
    ) -> Result<QueryCodeHashResponse> {
        let code_id = code_id.into();
        let msg = QueryByCodeIdRequest { code_id };
        let response = self.inner.code_hash_by_code_id(msg).await.unwrap();

        Ok(response.into_inner())
    }
}

impl crate::Client {
    pub async fn compute_contract_info(
        &self,
        contract_address: impl Into<String>,
    ) -> Result<QueryContractInfoResponse> {
        let contract_address = contract_address.into();

        let path = "/secret.compute.v1beta1.Query/ContractInfo";
        let msg = QueryByContractAddressRequest { contract_address };

        self.query_with_msg(path, msg)
            .await
            .and_then(try_decode_response::<QueryContractInfoResponse>)
    }

    pub async fn compute_contracts_by_code_id(
        &self,
        code_id: impl Into<u64>,
    ) -> Result<QueryContractsByCodeIdResponse> {
        let code_id = code_id.into();

        let path = "/secret.compute.v1beta1.Query/ContractsByCodeId";
        let msg = QueryByCodeIdRequest { code_id };

        self.query_with_msg(path, msg)
            .await
            .and_then(try_decode_response::<QueryContractsByCodeIdResponse>)
    }

    pub async fn compute_code(&self, code_id: impl Into<u64>) -> Result<QueryCodeResponse> {
        let code_id = code_id.into();

        let path = "/secret.compute.v1beta1.Query/Code";
        let msg = QueryByCodeIdRequest { code_id };

        self.query_with_msg(path, msg)
            .await
            .and_then(try_decode_response::<QueryCodeResponse>)
    }

    pub async fn compute_codes(&self) -> Result<QueryCodesResponse> {
        todo!()
    }

    pub async fn compute_code_hash_by_contract_address(&self) -> Result<QueryCodeHashResponse> {
        todo!()
    }

    pub async fn compute_code_hash_by_code_id(&self) -> Result<QueryCodeHashResponse> {
        todo!()
    }

    pub async fn compute_label_by_address(&self) -> Result<QueryContractLabelResponse> {
        todo!()
    }

    pub async fn compute_address_by_label(&self) -> Result<QueryContractAddressResponse> {
        todo!()
    }

    pub async fn compute_query_contract<T>(&self) -> Result<T> {
        todo!()
    }

    pub async fn compute_contract_history<T>(&self) -> Result<QueryContractHistoryResponse> {
        todo!()
    }
}
