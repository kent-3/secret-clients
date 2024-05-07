# GetTxsEventResponseTxResponsesInner

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**height** | Option<**String**> |  | [optional]
**txhash** | Option<**String**> | The transaction hash. | [optional]
**codespace** | Option<**String**> |  | [optional]
**code** | Option<**i64**> | Response code. | [optional]
**data** | Option<**String**> | Result bytes, if any. | [optional]
**raw_log** | Option<**String**> | The output of the application's logger (raw string). May be non-deterministic. | [optional]
**logs** | Option<[**Vec<crate::models::GetTxsEventResponseTxResponsesInnerLogsInner>**](GetTxsEvent_response_tx_responses_inner_logs_inner.md)> | The output of the application's logger (typed). May be non-deterministic. | [optional]
**info** | Option<**String**> | Additional information. May be non-deterministic. | [optional]
**gas_wanted** | Option<**String**> | Amount of gas requested for transaction. | [optional]
**gas_used** | Option<**String**> | Amount of gas consumed by transaction. | [optional]
**tx** | Option<[**crate::models::AccountsAreTheExistingAccountsInner**](accounts_are_the_existing_accounts_inner.md)> |  | [optional]
**timestamp** | Option<**String**> | Time of the previous block. For heights > 1, it's the weighted median of the timestamps of the valid votes in the block.LastCommit. For height == 1, it's genesis time. | [optional]
**events** | Option<[**Vec<crate::models::SimulateResponseResultEventsInner>**](Simulate_response_result_events_inner.md)> | Events defines all the events emitted by processing a transaction. Note, these events include those emitted by processing all the messages and those emitted from the ante handler. Whereas Logs contains the events, with additional metadata, emitted only by processing the messages.  Since: cosmos-sdk 0.42.11, 0.44.5, 0.45 | [optional]

[Back to Model list](../README.md#documentation-for-models) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to README](../README.md)


