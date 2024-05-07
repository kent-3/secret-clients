# GetTxsEventResponseTxsInner

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**body** | Option<[**crate::models::BodyIsTheProcessableContentOfTheTransaction**](body_is_the_processable_content_of_the_transaction.md)> |  | [optional]
**auth_info** | Option<[**crate::models::AuthInfoIsTheAuthorizationRelatedContentOfTheTransactionSpecificallySignersSignerModesAndFee**](auth_info_is_the_authorization_related_content_of_the_transaction__specifically_signers__signer_modes_and_fee.md)> |  | [optional]
**signatures** | Option<**Vec<String>**> | signatures is a list of signatures that matches the length and order of AuthInfo's signer_infos to allow connecting signature meta information like public key and signing mode by position. | [optional]

[Back to Model list](../README.md#documentation-for-models) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to README](../README.md)


