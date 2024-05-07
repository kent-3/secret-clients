# CosmosBaseAbciV1beta1Result

## Properties

| Name       | Type                                                                                                              | Description                                                                                                                                         | Notes      |
| ---------- | ----------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------- | ---------- |
| **data**   | Option<**String**>                                                                                                | Data is any data returned from message or handler execution. It MUST be length prefixed in order to separate data from multiple message executions. | [optional] |
| **log**    | Option<**String**>                                                                                                | Log contains the log information from message or handler execution.                                                                                 | [optional] |
| **events** | Option<[**Vec<crate::models::SimulateResponseResultEventsInner>**](Simulate_response_result_events_inner.md)> | Events contains a slice of Event objects that were emitted during message or handler execution.                                                     | [optional] |

[Back to Model list](../README.md#documentation-for-models) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to README](../README.md)
