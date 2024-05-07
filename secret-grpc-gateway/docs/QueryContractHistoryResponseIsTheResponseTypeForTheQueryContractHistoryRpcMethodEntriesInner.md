# QueryContractHistoryResponseIsTheResponseTypeForTheQueryContractHistoryRpcMethodEntriesInner

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**operation** | Option<**String**> | - CONTRACT_CODE_HISTORY_OPERATION_TYPE_UNSPECIFIED: ContractCodeHistoryOperationTypeUnspecified placeholder for empty value  - CONTRACT_CODE_HISTORY_OPERATION_TYPE_INIT: ContractCodeHistoryOperationTypeInit on chain contract instantiation  - CONTRACT_CODE_HISTORY_OPERATION_TYPE_MIGRATE: ContractCodeHistoryOperationTypeMigrate code migration  - CONTRACT_CODE_HISTORY_OPERATION_TYPE_GENESIS: ContractCodeHistoryOperationTypeGenesis based on genesis data | [optional][default to Unspecified]
**code_id** | Option<**String**> |  | [optional]
**updated** | Option<[**crate::models::AbsoluteTxPositionCanBeUsedToSortContracts**](AbsoluteTxPosition_can_be_used_to_sort_contracts.md)> |  | [optional]
**msg** | Option<**String**> |  | [optional]

[Back to Model list](../README.md#documentation-for-models) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to README](../README.md)


