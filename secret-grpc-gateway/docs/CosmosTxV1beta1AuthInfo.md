# CosmosTxV1beta1AuthInfo

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**signer_infos** | Option<[**Vec<crate::models::AuthInfoIsTheAuthorizationRelatedContentOfTheTransactionSpecificallySignersSignerModesAndFeeSignerInfosInner>**](auth_info_is_the_authorization_related_content_of_the_transaction__specifically_signers__signer_modes_and_fee_signer_infos_inner.md)> | signer_infos defines the signing modes for the required signers. The number and order of elements must match the required signers from TxBody's messages. The first element is the primary signer and the one which pays the fee. | [optional]
**fee** | Option<[**crate::models::AuthInfoIsTheAuthorizationRelatedContentOfTheTransactionSpecificallySignersSignerModesAndFeeFee**](auth_info_is_the_authorization_related_content_of_the_transaction__specifically_signers__signer_modes_and_fee_fee.md)> |  | [optional]

[Back to Model list](../README.md#documentation-for-models) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to README](../README.md)


