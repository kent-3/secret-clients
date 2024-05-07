# DelegatorValidatorsInfoResponseValidatorsInner

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**operator_address** | Option<**String**> | operator_address defines the address of the validator's operator; bech encoded in JSON. | [optional]
**consensus_pubkey** | Option<[**crate::models::AccountsAreTheExistingAccountsInner**](accounts_are_the_existing_accounts_inner.md)> |  | [optional]
**jailed** | Option<**bool**> | jailed defined whether the validator has been jailed from bonded status or not. | [optional]
**status** | Option<**String**> | status is the validator status (bonded/unbonding/unbonded). | [optional][default to Unspecified]
**tokens** | Option<**String**> | tokens define the delegated tokens (incl. self-delegation). | [optional]
**delegator_shares** | Option<**String**> | delegator_shares defines total shares issued to a validator's delegators. | [optional]
**description** | Option<[**crate::models::DelegatorValidatorsInfoResponseValidatorsInnerDescription**](DelegatorValidatorsInfo_response_validators_inner_description.md)> |  | [optional]
**unbonding_height** | Option<**String**> | unbonding_height defines, if unbonding, the height at which this validator has begun unbonding. | [optional]
**unbonding_time** | Option<**String**> | unbonding_time defines, if unbonding, the min time for the validator to complete unbonding. | [optional]
**commission** | Option<[**crate::models::DelegatorValidatorsInfoResponseValidatorsInnerCommission**](DelegatorValidatorsInfo_response_validators_inner_commission.md)> |  | [optional]
**min_self_delegation** | Option<**String**> | min_self_delegation is the validator's self declared minimum self delegation. | [optional]

[Back to Model list](../README.md#documentation-for-models) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to README](../README.md)


