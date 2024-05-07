# GovProposalsParamChangePostRequest

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**base_req** | Option<[**crate::models::BankAccountsAddressTransfersPostRequestBaseReq**](_bank_accounts__address__transfers_post_request_base_req.md)> |  | [optional]
**title** | Option<**String**> |  | [optional]
**description** | Option<**String**> |  | [optional]
**proposer** | Option<**String**> | bech32 encoded address | [optional]
**deposit** | Option<[**Vec<crate::models::TxsHashGetResponseTxFeeAmountInner>**](_txs__hash__get_response_tx_fee_amount_inner.md)> |  | [optional]
**changes** | Option<[**Vec<crate::models::GovProposalsParamChangePostRequestChangesInner>**](_gov_proposals_param_change_post_request_changes_inner.md)> |  | [optional]

[Back to Model list](../README.md#documentation-for-models) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to README](../README.md)


