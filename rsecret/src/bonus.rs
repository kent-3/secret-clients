use crate::wallet::{AminoSigner, DirectSigner, Signer};
use crate::{Result, SecretNetworkClient};
use secretrs::proto::cosmos::staking::v1beta1::{BondStatus, Validator};
use tonic::codegen::{Body, Bytes, StdError};
use tracing::debug;

impl<T, S> SecretNetworkClient<T, S>
where
    T: tonic::client::GrpcService<tonic::body::BoxBody>,
    T::Error: Into<StdError>,
    T::ResponseBody: Body<Data = Bytes> + Send + 'static,
    <T::ResponseBody as Body>::Error: Into<StdError> + Send,
    T: Clone,
    S: Signer,
    <S as AminoSigner>::Error: std::error::Error + Send + Sync + 'static,
    <S as DirectSigner>::Error: std::error::Error + Send + Sync + 'static,
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
