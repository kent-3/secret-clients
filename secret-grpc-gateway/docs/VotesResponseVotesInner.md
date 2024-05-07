# VotesResponseVotesInner

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**proposal_id** | Option<**String**> |  | [optional]
**voter** | Option<**String**> |  | [optional]
**option** | Option<**String**> | Deprecated: Prefer to use `options` instead. This field is set in queries if and only if `len(options) == 1` and that option has weight 1. In all other cases, this field will default to VOTE_OPTION_UNSPECIFIED. | [optional][default to Unspecified]
**options** | Option<[**Vec<crate::models::SinceCosmosSdk043Inner>**](Since__cosmos_sdk_0_43_inner.md)> |  | [optional]

[Back to Model list](../README.md#documentation-for-models) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to README](../README.md)


