# DenomUnitsRepresentsTheListOfDenomUnitSForAGivenCoinInner

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**denom** | Option<**String**> | denom represents the string name of the given denom unit (e.g uatom). | [optional]
**exponent** | Option<**i64**> | exponent represents power of 10 exponent that one must raise the base_denom to in order to equal the given DenomUnit's denom 1 denom = 1^exponent base_denom (e.g. with a base_denom of uatom, one can create a DenomUnit of 'atom' with exponent = 6, thus: 1 atom = 10^6 uatom). | [optional]
**aliases** | Option<**Vec<String>**> |  | [optional]

[Back to Model list](../README.md#documentation-for-models) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to README](../README.md)


