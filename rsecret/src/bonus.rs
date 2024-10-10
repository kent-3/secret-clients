use crate::{wallet::Signer, Result, SecretNetworkClient};
use secretrs::{
    proto::cosmos::staking::v1beta1::{BondStatus, Validator},
    utils::encryption::SecretUtils,
};
use tracing::{debug, info};

impl<T, U, S> SecretNetworkClient<T, U, S>
where
    T: tonic::client::GrpcService<tonic::body::BoxBody>,
    T::Error: Into<tonic::codegen::StdError>,
    T::ResponseBody: tonic::codegen::Body<Data = tonic::codegen::Bytes> + Send + 'static,
    <T::ResponseBody as tonic::codegen::Body>::Error: Into<tonic::codegen::StdError> + Send,
    T: Clone + Sync,
    U: SecretUtils + Sync,
    S: Signer + Sync,
{
    pub async fn all_validators(&self) -> Result<Vec<Validator>> {
        use secretrs::proto::cosmos::base::query::v1beta1::PageRequest;
        use secretrs::proto::cosmos::staking::v1beta1::QueryValidatorsRequest;

        let mut all_validators = Vec::new();
        let status = BondStatus::Bonded;
        let mut current_page = Some(PageRequest {
            key: vec![],
            offset: 0,
            limit: 100,
            count_total: true,
            reverse: false,
        });

        loop {
            let request = QueryValidatorsRequest {
                status: status.as_str_name().to_string(),
                pagination: current_page.clone(),
            };
            let response = self.query.staking.inner.clone().validators(request).await?;
            let response = response.into_inner();
            let validators = response.validators;
            all_validators.extend(validators);

            if let Some(page_response) = response.pagination {
                debug!("{:?}", current_page.as_ref().unwrap());
                debug!("{:?}", page_response);
                if page_response.next_key.is_empty() {
                    break;
                } else {
                    current_page = Some(PageRequest {
                        key: page_response.next_key,
                        ..current_page.unwrap_or_default()
                    });
                }
            } else {
                break;
            }
        }

        Ok(all_validators)
    }
}
