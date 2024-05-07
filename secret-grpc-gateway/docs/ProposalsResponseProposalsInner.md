# ProposalsResponseProposalsInner

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**proposal_id** | Option<**String**> |  | [optional]
**content** | Option<[**crate::models::AccountsAreTheExistingAccountsInner**](accounts_are_the_existing_accounts_inner.md)> |  | [optional]
**status** | Option<**String**> | ProposalStatus enumerates the valid statuses of a proposal.   - PROPOSAL_STATUS_UNSPECIFIED: PROPOSAL_STATUS_UNSPECIFIED defines the default propopsal status.  - PROPOSAL_STATUS_DEPOSIT_PERIOD: PROPOSAL_STATUS_DEPOSIT_PERIOD defines a proposal status during the deposit period.  - PROPOSAL_STATUS_VOTING_PERIOD: PROPOSAL_STATUS_VOTING_PERIOD defines a proposal status during the voting period.  - PROPOSAL_STATUS_PASSED: PROPOSAL_STATUS_PASSED defines a proposal status of a proposal that has passed.  - PROPOSAL_STATUS_REJECTED: PROPOSAL_STATUS_REJECTED defines a proposal status of a proposal that has been rejected.  - PROPOSAL_STATUS_FAILED: PROPOSAL_STATUS_FAILED defines a proposal status of a proposal that has failed. | [optional][default to Unspecified]
**final_tally_result** | Option<[**crate::models::ProposalsResponseProposalsInnerFinalTallyResult**](Proposals_response_proposals_inner_final_tally_result.md)> |  | [optional]
**submit_time** | Option<**String**> |  | [optional]
**deposit_end_time** | Option<**String**> |  | [optional]
**total_deposit** | Option<[**Vec<crate::models::AllBalancesResponseBalancesInner>**](AllBalances_response_balances_inner.md)> |  | [optional]
**voting_start_time** | Option<**String**> |  | [optional]
**voting_end_time** | Option<**String**> |  | [optional]
**is_expedited** | Option<**bool**> |  | [optional]

[Back to Model list](../README.md#documentation-for-models) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to README](../README.md)


