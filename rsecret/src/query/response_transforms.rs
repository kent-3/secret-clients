use secretrs::proto;
use secretrs::tendermint::block::{Block, Id};
use secretrs::{Error, ErrorReport, Result};

#[derive(Debug, Clone)]
pub struct GetLatestBlockResponse {
    pub block_id: Id,
    pub block: Block,
}

impl TryFrom<proto::cosmos::base::tendermint::v1beta1::GetLatestBlockResponse>
    for GetLatestBlockResponse
{
    type Error = ErrorReport;

    fn try_from(
        proto: proto::cosmos::base::tendermint::v1beta1::GetLatestBlockResponse,
    ) -> Result<GetLatestBlockResponse> {
        Ok(GetLatestBlockResponse {
            block_id: proto
                .block_id
                .ok_or(Error::MissingField { name: "block_id" })?
                .try_into()?,
            block: proto
                .block
                .ok_or(Error::MissingField { name: "block" })?
                .try_into()?,
        })
    }
}

impl From<GetLatestBlockResponse>
    for proto::cosmos::base::tendermint::v1beta1::GetLatestBlockResponse
{
    fn from(value: GetLatestBlockResponse) -> Self {
        Self {
            block_id: Some(value.block_id.into()),
            block: Some(value.block.into()),
            sdk_block: None,
        }
    }
}
