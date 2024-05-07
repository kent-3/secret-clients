# CosmosBankV1beta1Metadata

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**description** | Option<**String**> |  | [optional]
**denom_units** | Option<[**Vec<crate::models::DenomUnitsRepresentsTheListOfDenomUnitSForAGivenCoinInner>**](denom_units_represents_the_list_of_DenomUnit_s_for_a_given_coin_inner.md)> |  | [optional]
**base** | Option<**String**> | base represents the base denom (should be the DenomUnit with exponent = 0). | [optional]
**display** | Option<**String**> | display indicates the suggested denom that should be displayed in clients. | [optional]
**name** | Option<**String**> | Since: cosmos-sdk 0.43 | [optional]
**symbol** | Option<**String**> | symbol is the token symbol usually shown on exchanges (eg: ATOM). This can be the same as the display.  Since: cosmos-sdk 0.43 | [optional]

[Back to Model list](../README.md#documentation-for-models) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to README](../README.md)


