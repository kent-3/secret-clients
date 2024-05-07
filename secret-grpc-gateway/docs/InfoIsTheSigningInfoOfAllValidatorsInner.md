# InfoIsTheSigningInfoOfAllValidatorsInner

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**address** | Option<**String**> |  | [optional]
**start_height** | Option<**String**> |  | [optional]
**index_offset** | Option<**String**> | Index which is incremented each time the validator was a bonded in a block and may have signed a precommit or not. This in conjunction with the `SignedBlocksWindow` param determines the index in the `MissedBlocksBitArray`. | [optional]
**jailed_until** | Option<**String**> | Timestamp until which the validator is jailed due to liveness downtime. | [optional]
**tombstoned** | Option<**bool**> | Whether or not a validator has been tombstoned (killed out of validator set). It is set once the validator commits an equivocation or for any other configured misbehiavor. | [optional]
**missed_blocks_counter** | Option<**String**> | A counter kept to avoid unnecessary array reads. Note that `Sum(MissedBlocksBitArray)` always equals `MissedBlocksCounter`. | [optional]

[Back to Model list](../README.md#documentation-for-models) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to README](../README.md)


