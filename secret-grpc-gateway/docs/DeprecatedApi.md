# \DeprecatedApi

All URIs are relative to _http://localhost_

| Method                                                                                                                                                                        | HTTP request                                                                      | Description                                                                     |
| ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------- | ------------------------------------------------------------------------------- |
| [**auth_accounts_address_get**](DeprecatedApi.md#auth_accounts_address_get)                                                                                                   | **GET** /auth/accounts/{address}                                                  | Get the account information on blockchain                                       |
| [**bank_accounts_address_transfers_post**](DeprecatedApi.md#bank_accounts_address_transfers_post)                                                                             | **POST** /bank/accounts/{address}/transfers                                       | Send coins from one account to another                                          |
| [**bank_balances_address_get**](DeprecatedApi.md#bank_balances_address_get)                                                                                                   | **GET** /bank/balances/{address}                                                  | Get the account balances                                                        |
| [**bank_total_denomination_get**](DeprecatedApi.md#bank_total_denomination_get)                                                                                               | **GET** /bank/total/{denomination}                                                | Total supply of a single coin denomination                                      |
| [**bank_total_get**](DeprecatedApi.md#bank_total_get)                                                                                                                         | **GET** /bank/total                                                               | Total supply of coins in the chain                                              |
| [**blocks_height_get**](DeprecatedApi.md#blocks_height_get)                                                                                                                   | **GET** /blocks/{height}                                                          | Get a block at a certain height                                                 |
| [**blocks_latest_get**](DeprecatedApi.md#blocks_latest_get)                                                                                                                   | **GET** /blocks/latest                                                            | Get the latest block                                                            |
| [**consensus_io_exch_pubkey**](DeprecatedApi.md#consensus_io_exch_pubkey)                                                                                                     | **GET** /reg/consensus-io-exch-pubkey                                             | Get chain public key                                                            |
| [**distribution_community_pool_get**](DeprecatedApi.md#distribution_community_pool_get)                                                                                       | **GET** /distribution/community_pool                                              | Community pool parameters                                                       |
| [**distribution_delegators_delegator_addr_rewards_get**](DeprecatedApi.md#distribution_delegators_delegator_addr_rewards_get)                                                 | **GET** /distribution/delegators/{delegatorAddr}/rewards                          | Get the total rewards balance from all delegations                              |
| [**distribution_delegators_delegator_addr_rewards_post**](DeprecatedApi.md#distribution_delegators_delegator_addr_rewards_post)                                               | **POST** /distribution/delegators/{delegatorAddr}/rewards                         | Withdraw all the delegator's delegation rewards                                 |
| [**distribution_delegators_delegator_addr_rewards_validator_addr_get**](DeprecatedApi.md#distribution_delegators_delegator_addr_rewards_validator_addr_get)                   | **GET** /distribution/delegators/{delegatorAddr}/rewards/{validatorAddr}          | Query a delegation reward                                                       |
| [**distribution_delegators_delegator_addr_rewards_validator_addr_post**](DeprecatedApi.md#distribution_delegators_delegator_addr_rewards_validator_addr_post)                 | **POST** /distribution/delegators/{delegatorAddr}/rewards/{validatorAddr}         | Withdraw a delegation reward                                                    |
| [**distribution_delegators_delegator_addr_withdraw_address_get**](DeprecatedApi.md#distribution_delegators_delegator_addr_withdraw_address_get)                               | **GET** /distribution/delegators/{delegatorAddr}/withdraw_address                 | Get the rewards withdrawal address                                              |
| [**distribution_delegators_delegator_addr_withdraw_address_post**](DeprecatedApi.md#distribution_delegators_delegator_addr_withdraw_address_post)                             | **POST** /distribution/delegators/{delegatorAddr}/withdraw_address                | Replace the rewards withdrawal address                                          |
| [**distribution_parameters_get**](DeprecatedApi.md#distribution_parameters_get)                                                                                               | **GET** /distribution/parameters                                                  | Fee distribution parameters                                                     |
| [**distribution_validators_validator_addr_get**](DeprecatedApi.md#distribution_validators_validator_addr_get)                                                                 | **GET** /distribution/validators/{validatorAddr}                                  | Validator distribution information                                              |
| [**distribution_validators_validator_addr_outstanding_rewards_get**](DeprecatedApi.md#distribution_validators_validator_addr_outstanding_rewards_get)                         | **GET** /distribution/validators/{validatorAddr}/outstanding_rewards              | Fee distribution outstanding rewards of a single validator                      |
| [**distribution_validators_validator_addr_rewards_get**](DeprecatedApi.md#distribution_validators_validator_addr_rewards_get)                                                 | **GET** /distribution/validators/{validatorAddr}/rewards                          | Commission and self-delegation rewards of a single validator                    |
| [**distribution_validators_validator_addr_rewards_post**](DeprecatedApi.md#distribution_validators_validator_addr_rewards_post)                                               | **POST** /distribution/validators/{validatorAddr}/rewards                         | Withdraw the validator's rewards                                                |
| [**gov_parameters_deposit_get**](DeprecatedApi.md#gov_parameters_deposit_get)                                                                                                 | **GET** /gov/parameters/deposit                                                   | Query governance deposit parameters                                             |
| [**gov_parameters_tallying_get**](DeprecatedApi.md#gov_parameters_tallying_get)                                                                                               | **GET** /gov/parameters/tallying                                                  | Query governance tally parameters                                               |
| [**gov_parameters_voting_get**](DeprecatedApi.md#gov_parameters_voting_get)                                                                                                   | **GET** /gov/parameters/voting                                                    | Query governance voting parameters                                              |
| [**gov_proposals_get**](DeprecatedApi.md#gov_proposals_get)                                                                                                                   | **GET** /gov/proposals                                                            | Query proposals                                                                 |
| [**gov_proposals_param_change_post**](DeprecatedApi.md#gov_proposals_param_change_post)                                                                                       | **POST** /gov/proposals/param_change                                              | Generate a parameter change proposal transaction                                |
| [**gov_proposals_post**](DeprecatedApi.md#gov_proposals_post)                                                                                                                 | **POST** /gov/proposals                                                           | Submit a proposal                                                               |
| [**gov_proposals_proposal_id_deposits_depositor_get**](DeprecatedApi.md#gov_proposals_proposal_id_deposits_depositor_get)                                                     | **GET** /gov/proposals/{proposalId}/deposits/{depositor}                          | Query deposit                                                                   |
| [**gov_proposals_proposal_id_deposits_get**](DeprecatedApi.md#gov_proposals_proposal_id_deposits_get)                                                                         | **GET** /gov/proposals/{proposalId}/deposits                                      | Query deposits                                                                  |
| [**gov_proposals_proposal_id_deposits_post**](DeprecatedApi.md#gov_proposals_proposal_id_deposits_post)                                                                       | **POST** /gov/proposals/{proposalId}/deposits                                     | Deposit tokens to a proposal                                                    |
| [**gov_proposals_proposal_id_get**](DeprecatedApi.md#gov_proposals_proposal_id_get)                                                                                           | **GET** /gov/proposals/{proposalId}                                               | Query a proposal                                                                |
| [**gov_proposals_proposal_id_proposer_get**](DeprecatedApi.md#gov_proposals_proposal_id_proposer_get)                                                                         | **GET** /gov/proposals/{proposalId}/proposer                                      | Query proposer                                                                  |
| [**gov_proposals_proposal_id_tally_get**](DeprecatedApi.md#gov_proposals_proposal_id_tally_get)                                                                               | **GET** /gov/proposals/{proposalId}/tally                                         | Get a proposal's tally result at the current time                               |
| [**gov_proposals_proposal_id_votes_get**](DeprecatedApi.md#gov_proposals_proposal_id_votes_get)                                                                               | **GET** /gov/proposals/{proposalId}/votes                                         | Query voters                                                                    |
| [**gov_proposals_proposal_id_votes_post**](DeprecatedApi.md#gov_proposals_proposal_id_votes_post)                                                                             | **POST** /gov/proposals/{proposalId}/votes                                        | Vote a proposal                                                                 |
| [**gov_proposals_proposal_id_votes_voter_get**](DeprecatedApi.md#gov_proposals_proposal_id_votes_voter_get)                                                                   | **GET** /gov/proposals/{proposalId}/votes/{voter}                                 | Query vote                                                                      |
| [**minting_annual_provisions_get**](DeprecatedApi.md#minting_annual_provisions_get)                                                                                           | **GET** /minting/annual-provisions                                                | Current minting annual provisions value                                         |
| [**minting_inflation_get**](DeprecatedApi.md#minting_inflation_get)                                                                                                           | **GET** /minting/inflation                                                        | Current minting inflation value                                                 |
| [**minting_parameters_get**](DeprecatedApi.md#minting_parameters_get)                                                                                                         | **GET** /minting/parameters                                                       | Minting module parameters                                                       |
| [**node_info_get**](DeprecatedApi.md#node_info_get)                                                                                                                           | **GET** /node_info                                                                | The properties of the connected node                                            |
| [**slashing_parameters_get**](DeprecatedApi.md#slashing_parameters_get)                                                                                                       | **GET** /slashing/parameters                                                      | Get the current slashing parameters                                             |
| [**slashing_signing_infos_get**](DeprecatedApi.md#slashing_signing_infos_get)                                                                                                 | **GET** /slashing/signing_infos                                                   | Get sign info of given all validators                                           |
| [**slashing_validators_validator_addr_unjail_post**](DeprecatedApi.md#slashing_validators_validator_addr_unjail_post)                                                         | **POST** /slashing/validators/{validatorAddr}/unjail                              | Unjail a jailed validator                                                       |
| [**staking_delegators_delegator_addr_delegations_get**](DeprecatedApi.md#staking_delegators_delegator_addr_delegations_get)                                                   | **GET** /staking/delegators/{delegatorAddr}/delegations                           | Get all delegations from a delegator                                            |
| [**staking_delegators_delegator_addr_delegations_post**](DeprecatedApi.md#staking_delegators_delegator_addr_delegations_post)                                                 | **POST** /staking/delegators/{delegatorAddr}/delegations                          | Submit delegation                                                               |
| [**staking_delegators_delegator_addr_delegations_validator_addr_get**](DeprecatedApi.md#staking_delegators_delegator_addr_delegations_validator_addr_get)                     | **GET** /staking/delegators/{delegatorAddr}/delegations/{validatorAddr}           | Query the current delegation between a delegator and a validator                |
| [**staking_delegators_delegator_addr_redelegations_post**](DeprecatedApi.md#staking_delegators_delegator_addr_redelegations_post)                                             | **POST** /staking/delegators/{delegatorAddr}/redelegations                        | Submit a redelegation                                                           |
| [**staking_delegators_delegator_addr_unbonding_delegations_get**](DeprecatedApi.md#staking_delegators_delegator_addr_unbonding_delegations_get)                               | **GET** /staking/delegators/{delegatorAddr}/unbonding_delegations                 | Get all unbonding delegations from a delegator                                  |
| [**staking_delegators_delegator_addr_unbonding_delegations_post**](DeprecatedApi.md#staking_delegators_delegator_addr_unbonding_delegations_post)                             | **POST** /staking/delegators/{delegatorAddr}/unbonding_delegations                | Submit an unbonding delegation                                                  |
| [**staking_delegators_delegator_addr_unbonding_delegations_validator_addr_get**](DeprecatedApi.md#staking_delegators_delegator_addr_unbonding_delegations_validator_addr_get) | **GET** /staking/delegators/{delegatorAddr}/unbonding_delegations/{validatorAddr} | Query all unbonding delegations between a delegator and a validator             |
| [**staking_delegators_delegator_addr_validators_get**](DeprecatedApi.md#staking_delegators_delegator_addr_validators_get)                                                     | **GET** /staking/delegators/{delegatorAddr}/validators                            | Query all validators that a delegator is bonded to                              |
| [**staking_delegators_delegator_addr_validators_validator_addr_get**](DeprecatedApi.md#staking_delegators_delegator_addr_validators_validator_addr_get)                       | **GET** /staking/delegators/{delegatorAddr}/validators/{validatorAddr}            | Query a validator that a delegator is bonded to                                 |
| [**staking_parameters_get**](DeprecatedApi.md#staking_parameters_get)                                                                                                         | **GET** /staking/parameters                                                       | Get the current staking parameter values                                        |
| [**staking_pool_get**](DeprecatedApi.md#staking_pool_get)                                                                                                                     | **GET** /staking/pool                                                             | Get the current state of the staking pool                                       |
| [**staking_redelegations_get**](DeprecatedApi.md#staking_redelegations_get)                                                                                                   | **GET** /staking/redelegations                                                    | Get all redelegations (filter by query params)                                  |
| [**staking_validators_get**](DeprecatedApi.md#staking_validators_get)                                                                                                         | **GET** /staking/validators                                                       | Get all validator candidates. By default it returns only the bonded validators. |
| [**staking_validators_validator_addr_delegations_get**](DeprecatedApi.md#staking_validators_validator_addr_delegations_get)                                                   | **GET** /staking/validators/{validatorAddr}/delegations                           | Get all delegations from a validator                                            |
| [**staking_validators_validator_addr_get**](DeprecatedApi.md#staking_validators_validator_addr_get)                                                                           | **GET** /staking/validators/{validatorAddr}                                       | Query the information from a single validator                                   |
| [**staking_validators_validator_addr_unbonding_delegations_get**](DeprecatedApi.md#staking_validators_validator_addr_unbonding_delegations_get)                               | **GET** /staking/validators/{validatorAddr}/unbonding_delegations                 | Get all unbonding delegations from a validator                                  |
| [**syncing_get**](DeprecatedApi.md#syncing_get)                                                                                                                               | **GET** /syncing                                                                  | Syncing state of node                                                           |
| [**txs_decode_post**](DeprecatedApi.md#txs_decode_post)                                                                                                                       | **POST** /txs/decode                                                              | Decode a transaction from the Amino wire format                                 |
| [**txs_encode_post**](DeprecatedApi.md#txs_encode_post)                                                                                                                       | **POST** /txs/encode                                                              | Encode a transaction to the Amino wire format                                   |
| [**txs_get**](DeprecatedApi.md#txs_get)                                                                                                                                       | **GET** /txs                                                                      | Search transactions                                                             |
| [**txs_hash_get**](DeprecatedApi.md#txs_hash_get)                                                                                                                             | **GET** /txs/{hash}                                                               | Get a Tx by hash                                                                |
| [**txs_post**](DeprecatedApi.md#txs_post)                                                                                                                                     | **POST** /txs                                                                     | Broadcast a signed tx                                                           |
| [**validatorsets_height_get**](DeprecatedApi.md#validatorsets_height_get)                                                                                                     | **GET** /validatorsets/{height}                                                   | Get a validator set a certain height                                            |
| [**validatorsets_latest_get**](DeprecatedApi.md#validatorsets_latest_get)                                                                                                     | **GET** /validatorsets/latest                                                     | Get the latest validator set                                                    |
| [**wasm_code_code_id_contracts_get**](DeprecatedApi.md#wasm_code_code_id_contracts_get)                                                                                       | **GET** /wasm/code/{codeID}/contracts                                             | Get info about all contracts deployed with a code ID                            |
| [**wasm_code_code_id_get**](DeprecatedApi.md#wasm_code_code_id_get)                                                                                                           | **GET** /wasm/code/{codeID}                                                       | Get code info of the code ID                                                    |
| [**wasm_code_code_id_hash_get**](DeprecatedApi.md#wasm_code_code_id_hash_get)                                                                                                 | **GET** /wasm/code/{codeID}/hash                                                  | Get code ID data hash                                                           |
| [**wasm_code_code_id_post**](DeprecatedApi.md#wasm_code_code_id_post)                                                                                                         | **POST** /wasm/code/{codeID}                                                      | Instantiate wasm contract message                                               |
| [**wasm_code_get**](DeprecatedApi.md#wasm_code_get)                                                                                                                           | **GET** /wasm/code                                                                | List code info                                                                  |
| [**wasm_code_post**](DeprecatedApi.md#wasm_code_post)                                                                                                                         | **POST** /wasm/code                                                               | Generate wasm store code message                                                |
| [**wasm_contract_contract_address_code_hash_get**](DeprecatedApi.md#wasm_contract_contract_address_code_hash_get)                                                             | **GET** /wasm/contract/{contractAddress}/code-hash                                | Get stored contract-hash information                                            |
| [**wasm_contract_contract_address_post**](DeprecatedApi.md#wasm_contract_contract_address_post)                                                                               | **POST** /wasm/contract/{contractAddress}                                         | Execute wasm contract message                                                   |
| [**wasm_contract_contract_address_query_query_get**](DeprecatedApi.md#wasm_contract_contract_address_query_query_get)                                                         | **GET** /wasm/contract/{contractAddress}/query/{query}                            | Get stored information with store key                                           |

## auth_accounts_address_get

> crate::models::AuthAccountsAddressGetResponse auth_accounts_address_get(address)
> Get the account information on blockchain

### Parameters

| Name        | Type       | Description     | Required   | Notes |
| ----------- | ---------- | --------------- | ---------- | ----- |
| **address** | **String** | Account address | [required] |

### Return type

[**crate::models::AuthAccountsAddressGetResponse**](_auth_accounts__address__get_response.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)

## bank_accounts_address_transfers_post

> crate::models::TxsHashGetResponseTx bank_accounts_address_transfers_post(address, bank_accounts_address_transfers_post_request)
> Send coins from one account to another

### Parameters

| Name                                             | Type                                                                                      | Description                      | Required   | Notes |
| ------------------------------------------------ | ----------------------------------------------------------------------------------------- | -------------------------------- | ---------- | ----- |
| **address**                                      | **String**                                                                                | Account address in bech32 format | [required] |
| **bank_accounts_address_transfers_post_request** | [**BankAccountsAddressTransfersPostRequest**](BankAccountsAddressTransfersPostRequest.md) | The sender and tx information    | [required] |

### Return type

[**crate::models::TxsHashGetResponseTx**](_txs__hash__get_response_tx.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)

## bank_balances_address_get

> Vec<crate::models::TxsHashGetResponseTxFeeAmountInner> bank_balances_address_get(address)
> Get the account balances

### Parameters

| Name        | Type       | Description                      | Required   | Notes |
| ----------- | ---------- | -------------------------------- | ---------- | ----- |
| **address** | **String** | Account address in bech32 format | [required] |

### Return type

[**Vec<crate::models::TxsHashGetResponseTxFeeAmountInner>**](_txs__hash__get_response_tx_fee_amount_inner.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)

## bank_total_denomination_get

> String bank_total_denomination_get(denomination)
> Total supply of a single coin denomination

### Parameters

| Name             | Type       | Description       | Required   | Notes |
| ---------------- | ---------- | ----------------- | ---------- | ----- |
| **denomination** | **String** | Coin denomination | [required] |

### Return type

**String**

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)

## bank_total_get

> crate::models::BankTotalGetResponse bank_total_get()
> Total supply of coins in the chain

### Parameters

This endpoint does not need any parameter.

### Return type

[**crate::models::BankTotalGetResponse**](_bank_total_get_response.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)

## blocks_height_get

> crate::models::BlocksLatestGetResponse blocks_height_get(height)
> Get a block at a certain height

### Parameters

| Name       | Type    | Description  | Required   | Notes |
| ---------- | ------- | ------------ | ---------- | ----- |
| **height** | **f32** | Block height | [required] |

### Return type

[**crate::models::BlocksLatestGetResponse**](_blocks_latest_get_response.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)

## blocks_latest_get

> crate::models::BlocksLatestGetResponse blocks_latest_get()
> Get the latest block

### Parameters

This endpoint does not need any parameter.

### Return type

[**crate::models::BlocksLatestGetResponse**](_blocks_latest_get_response.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)

## consensus_io_exch_pubkey

> crate::models::ConsensusIoExchPubkeyResponse consensus_io_exch_pubkey()
> Get chain public key

Get chain public key

### Parameters

This endpoint does not need any parameter.

### Return type

[**crate::models::ConsensusIoExchPubkeyResponse**](consensus_io_exch_pubkey_response.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: _/_

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)

## distribution_community_pool_get

> Vec<crate::models::TxsHashGetResponseTxFeeAmountInner> distribution_community_pool_get()
> Community pool parameters

### Parameters

This endpoint does not need any parameter.

### Return type

[**Vec<crate::models::TxsHashGetResponseTxFeeAmountInner>**](_txs__hash__get_response_tx_fee_amount_inner.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)

## distribution_delegators_delegator_addr_rewards_get

> crate::models::DistributionDelegatorsDelegatorAddrRewardsGetResponse distribution_delegators_delegator_addr_rewards_get(delegator_addr)
> Get the total rewards balance from all delegations

Get the sum of all the rewards earned by delegations by a single delegator

### Parameters

| Name               | Type       | Description                    | Required   | Notes |
| ------------------ | ---------- | ------------------------------ | ---------- | ----- |
| **delegator_addr** | **String** | Bech32 AccAddress of Delegator | [required] |

### Return type

[**crate::models::DistributionDelegatorsDelegatorAddrRewardsGetResponse**](_distribution_delegators__delegatorAddr__rewards_get_response.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)

## distribution_delegators_delegator_addr_rewards_post

> crate::models::TxsHashGetResponseTx distribution_delegators_delegator_addr_rewards_post(delegator_addr, distribution_delegators_delegator_addr_rewards_post_request)
> Withdraw all the delegator's delegation rewards

Withdraw all the delegator's delegation rewards

### Parameters

| Name                                                            | Type                                                                                                                          | Description                    | Required   | Notes |
| --------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------- | ------------------------------ | ---------- | ----- |
| **delegator_addr**                                              | **String**                                                                                                                    | Bech32 AccAddress of Delegator | [required] |
| **distribution_delegators_delegator_addr_rewards_post_request** | Option<[**DistributionDelegatorsDelegatorAddrRewardsPostRequest**](DistributionDelegatorsDelegatorAddrRewardsPostRequest.md)> |                                |            |

### Return type

[**crate::models::TxsHashGetResponseTx**](_txs__hash__get_response_tx.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)

## distribution_delegators_delegator_addr_rewards_validator_addr_get

> Vec<crate::models::TxsHashGetResponseTxFeeAmountInner> distribution_delegators_delegator_addr_rewards_validator_addr_get(delegator_addr, validator_addr)
> Query a delegation reward

Query a single delegation reward by a delegator

### Parameters

| Name               | Type       | Description                         | Required   | Notes |
| ------------------ | ---------- | ----------------------------------- | ---------- | ----- |
| **delegator_addr** | **String** | Bech32 AccAddress of Delegator      | [required] |
| **validator_addr** | **String** | Bech32 OperatorAddress of validator | [required] |

### Return type

[**Vec<crate::models::TxsHashGetResponseTxFeeAmountInner>**](_txs__hash__get_response_tx_fee_amount_inner.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)

## distribution_delegators_delegator_addr_rewards_validator_addr_post

> crate::models::TxsHashGetResponseTx distribution_delegators_delegator_addr_rewards_validator_addr_post(delegator_addr, validator_addr, distribution_delegators_delegator_addr_rewards_post_request)
> Withdraw a delegation reward

Withdraw a delegator's delegation reward from a single validator

### Parameters

| Name                                                            | Type                                                                                                                          | Description                         | Required   | Notes |
| --------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------- | ----------------------------------- | ---------- | ----- |
| **delegator_addr**                                              | **String**                                                                                                                    | Bech32 AccAddress of Delegator      | [required] |
| **validator_addr**                                              | **String**                                                                                                                    | Bech32 OperatorAddress of validator | [required] |
| **distribution_delegators_delegator_addr_rewards_post_request** | Option<[**DistributionDelegatorsDelegatorAddrRewardsPostRequest**](DistributionDelegatorsDelegatorAddrRewardsPostRequest.md)> |                                     |            |

### Return type

[**crate::models::TxsHashGetResponseTx**](_txs__hash__get_response_tx.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)

## distribution_delegators_delegator_addr_withdraw_address_get

> String distribution_delegators_delegator_addr_withdraw_address_get(delegator_addr)
> Get the rewards withdrawal address

Get the delegations' rewards withdrawal address. This is the address in which the user will receive the reward funds

### Parameters

| Name               | Type       | Description                    | Required   | Notes |
| ------------------ | ---------- | ------------------------------ | ---------- | ----- |
| **delegator_addr** | **String** | Bech32 AccAddress of Delegator | [required] |

### Return type

**String**

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)

## distribution_delegators_delegator_addr_withdraw_address_post

> crate::models::TxsHashGetResponseTx distribution_delegators_delegator_addr_withdraw_address_post(delegator_addr, distribution_delegators_delegator_addr_withdraw_address_post_request)
> Replace the rewards withdrawal address

Replace the delegations' rewards withdrawal address for a new one.

### Parameters

| Name                                                                     | Type                                                                                                                                          | Description                    | Required   | Notes |
| ------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------ | ---------- | ----- |
| **delegator_addr**                                                       | **String**                                                                                                                                    | Bech32 AccAddress of Delegator | [required] |
| **distribution_delegators_delegator_addr_withdraw_address_post_request** | Option<[**DistributionDelegatorsDelegatorAddrWithdrawAddressPostRequest**](DistributionDelegatorsDelegatorAddrWithdrawAddressPostRequest.md)> |                                |            |

### Return type

[**crate::models::TxsHashGetResponseTx**](_txs__hash__get_response_tx.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)

## distribution_parameters_get

> crate::models::DistributionParametersGetResponse distribution_parameters_get()
> Fee distribution parameters

### Parameters

This endpoint does not need any parameter.

### Return type

[**crate::models::DistributionParametersGetResponse**](_distribution_parameters_get_response.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)

## distribution_validators_validator_addr_get

> crate::models::DistributionValidatorsValidatorAddrGetResponse distribution_validators_validator_addr_get(validator_addr)
> Validator distribution information

Query the distribution information of a single validator

### Parameters

| Name               | Type       | Description                         | Required   | Notes |
| ------------------ | ---------- | ----------------------------------- | ---------- | ----- |
| **validator_addr** | **String** | Bech32 OperatorAddress of validator | [required] |

### Return type

[**crate::models::DistributionValidatorsValidatorAddrGetResponse**](_distribution_validators__validatorAddr__get_response.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)

## distribution_validators_validator_addr_outstanding_rewards_get

> Vec<crate::models::TxsHashGetResponseTxFeeAmountInner> distribution_validators_validator_addr_outstanding_rewards_get(validator_addr)
> Fee distribution outstanding rewards of a single validator

### Parameters

| Name               | Type       | Description                         | Required   | Notes |
| ------------------ | ---------- | ----------------------------------- | ---------- | ----- |
| **validator_addr** | **String** | Bech32 OperatorAddress of validator | [required] |

### Return type

[**Vec<crate::models::TxsHashGetResponseTxFeeAmountInner>**](_txs__hash__get_response_tx_fee_amount_inner.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)

## distribution_validators_validator_addr_rewards_get

> Vec<crate::models::TxsHashGetResponseTxFeeAmountInner> distribution_validators_validator_addr_rewards_get(validator_addr)
> Commission and self-delegation rewards of a single validator

Query the commission and self-delegation rewards of validator.

### Parameters

| Name               | Type       | Description                         | Required   | Notes |
| ------------------ | ---------- | ----------------------------------- | ---------- | ----- |
| **validator_addr** | **String** | Bech32 OperatorAddress of validator | [required] |

### Return type

[**Vec<crate::models::TxsHashGetResponseTxFeeAmountInner>**](_txs__hash__get_response_tx_fee_amount_inner.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)

## distribution_validators_validator_addr_rewards_post

> crate::models::TxsHashGetResponseTx distribution_validators_validator_addr_rewards_post(validator_addr, distribution_delegators_delegator_addr_rewards_post_request)
> Withdraw the validator's rewards

Withdraw the validator's self-delegation and commissions rewards

### Parameters

| Name                                                            | Type                                                                                                                          | Description                         | Required   | Notes |
| --------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------- | ----------------------------------- | ---------- | ----- |
| **validator_addr**                                              | **String**                                                                                                                    | Bech32 OperatorAddress of validator | [required] |
| **distribution_delegators_delegator_addr_rewards_post_request** | Option<[**DistributionDelegatorsDelegatorAddrRewardsPostRequest**](DistributionDelegatorsDelegatorAddrRewardsPostRequest.md)> |                                     |            |

### Return type

[**crate::models::TxsHashGetResponseTx**](_txs__hash__get_response_tx.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)

## gov_parameters_deposit_get

> crate::models::GovParametersDepositGetResponse gov_parameters_deposit_get()
> Query governance deposit parameters

Query governance deposit parameters. The max_deposit_period units are in nanoseconds.

### Parameters

This endpoint does not need any parameter.

### Return type

[**crate::models::GovParametersDepositGetResponse**](_gov_parameters_deposit_get_response.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)

## gov_parameters_tallying_get

> crate::models::GovParametersTallyingGetResponse gov_parameters_tallying_get()
> Query governance tally parameters

Query governance tally parameters

### Parameters

This endpoint does not need any parameter.

### Return type

[**crate::models::GovParametersTallyingGetResponse**](_gov_parameters_tallying_get_response.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)

## gov_parameters_voting_get

> crate::models::GovParametersVotingGetResponse gov_parameters_voting_get()
> Query governance voting parameters

Query governance voting parameters. The voting_period units are in nanoseconds.

### Parameters

This endpoint does not need any parameter.

### Return type

[**crate::models::GovParametersVotingGetResponse**](_gov_parameters_voting_get_response.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)

## gov_proposals_get

> Vec<crate::models::GovProposalsGetResponseInner> gov_proposals_get(voter, depositor, status)
> Query proposals

Query proposals information with parameters

### Parameters

| Name          | Type               | Description                                                                                                  | Required | Notes |
| ------------- | ------------------ | ------------------------------------------------------------------------------------------------------------ | -------- | ----- |
| **voter**     | Option<**String**> | voter address                                                                                                |          |
| **depositor** | Option<**String**> | depositor address                                                                                            |          |
| **status**    | Option<**String**> | proposal status, valid values can be `\"deposit_period\"`, `\"voting_period\"`, `\"passed\"`, `\"rejected\"` |          |

### Return type

[**Vec<crate::models::GovProposalsGetResponseInner>**](_gov_proposals_get_response_inner.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)

## gov_proposals_param_change_post

> crate::models::TxsHashGetResponseTx gov_proposals_param_change_post(gov_proposals_param_change_post_request)
> Generate a parameter change proposal transaction

Generate a parameter change proposal transaction

### Parameters

| Name                                        | Type                                                                            | Description                                                            | Required   | Notes |
| ------------------------------------------- | ------------------------------------------------------------------------------- | ---------------------------------------------------------------------- | ---------- | ----- |
| **gov_proposals_param_change_post_request** | [**GovProposalsParamChangePostRequest**](GovProposalsParamChangePostRequest.md) | The parameter change proposal body that contains all parameter changes | [required] |

### Return type

[**crate::models::TxsHashGetResponseTx**](_txs__hash__get_response_tx.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)

## gov_proposals_post

> crate::models::TxsHashGetResponseTx gov_proposals_post(gov_proposals_post_request)
> Submit a proposal

Send transaction to submit a proposal

### Parameters

| Name                           | Type                                                      | Description                                                                                          | Required   | Notes |
| ------------------------------ | --------------------------------------------------------- | ---------------------------------------------------------------------------------------------------- | ---------- | ----- |
| **gov_proposals_post_request** | [**GovProposalsPostRequest**](GovProposalsPostRequest.md) | valid value of `\"proposal_type\"` can be `\"text\"`, `\"parameter_change\"`, `\"software_upgrade\"` | [required] |

### Return type

[**crate::models::TxsHashGetResponseTx**](_txs__hash__get_response_tx.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)

## gov_proposals_proposal_id_deposits_depositor_get

> crate::models::GovProposalsProposalIdDepositsGetResponseInner gov_proposals_proposal_id_deposits_depositor_get(proposal_id, depositor)
> Query deposit

Query deposit by proposalId and depositor address

### Parameters

| Name            | Type       | Description              | Required   | Notes |
| --------------- | ---------- | ------------------------ | ---------- | ----- |
| **proposal_id** | **String** | proposal id              | [required] |
| **depositor**   | **String** | Bech32 depositor address | [required] |

### Return type

[**crate::models::GovProposalsProposalIdDepositsGetResponseInner**](_gov_proposals__proposalId__deposits_get_response_inner.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)

## gov_proposals_proposal_id_deposits_get

> Vec<crate::models::GovProposalsProposalIdDepositsGetResponseInner> gov_proposals_proposal_id_deposits_get(proposal_id)
> Query deposits

Query deposits by proposalId

### Parameters

| Name            | Type       | Description | Required   | Notes |
| --------------- | ---------- | ----------- | ---------- | ----- |
| **proposal_id** | **String** |             | [required] |

### Return type

[**Vec<crate::models::GovProposalsProposalIdDepositsGetResponseInner>**](_gov_proposals__proposalId__deposits_get_response_inner.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)

## gov_proposals_proposal_id_deposits_post

> crate::models::TxsHashGetResponseTx gov_proposals_proposal_id_deposits_post(proposal_id, gov_proposals_proposal_id_deposits_post_request)
> Deposit tokens to a proposal

Send transaction to deposit tokens to a proposal

### Parameters

| Name                                                | Type                                                                                          | Description | Required   | Notes |
| --------------------------------------------------- | --------------------------------------------------------------------------------------------- | ----------- | ---------- | ----- |
| **proposal_id**                                     | **String**                                                                                    | proposal id | [required] |
| **gov_proposals_proposal_id_deposits_post_request** | [**GovProposalsProposalIdDepositsPostRequest**](GovProposalsProposalIdDepositsPostRequest.md) |             | [required] |

### Return type

[**crate::models::TxsHashGetResponseTx**](_txs__hash__get_response_tx.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)

## gov_proposals_proposal_id_get

> crate::models::GovProposalsGetResponseInner gov_proposals_proposal_id_get(proposal_id)
> Query a proposal

Query a proposal by id

### Parameters

| Name            | Type       | Description | Required   | Notes |
| --------------- | ---------- | ----------- | ---------- | ----- |
| **proposal_id** | **String** |             | [required] |

### Return type

[**crate::models::GovProposalsGetResponseInner**](_gov_proposals_get_response_inner.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)

## gov_proposals_proposal_id_proposer_get

> crate::models::GovProposalsProposalIdProposerGetResponse gov_proposals_proposal_id_proposer_get(proposal_id)
> Query proposer

Query for the proposer for a proposal

### Parameters

| Name            | Type       | Description | Required   | Notes |
| --------------- | ---------- | ----------- | ---------- | ----- |
| **proposal_id** | **String** |             | [required] |

### Return type

[**crate::models::GovProposalsProposalIdProposerGetResponse**](_gov_proposals__proposalId__proposer_get_response.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)

## gov_proposals_proposal_id_tally_get

> crate::models::GovProposalsGetResponseInnerFinalTallyResult gov_proposals_proposal_id_tally_get(proposal_id)
> Get a proposal's tally result at the current time

Gets a proposal's tally result at the current time. If the proposal is pending deposits (i.e status 'Deposit') it returns an empty tally result.

### Parameters

| Name            | Type       | Description | Required   | Notes |
| --------------- | ---------- | ----------- | ---------- | ----- |
| **proposal_id** | **String** | proposal id | [required] |

### Return type

[**crate::models::GovProposalsGetResponseInnerFinalTallyResult**](_gov_proposals_get_response_inner_final_tally_result.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)

## gov_proposals_proposal_id_votes_get

> Vec<crate::models::GovProposalsProposalIdVotesGetResponseInner> gov_proposals_proposal_id_votes_get(proposal_id)
> Query voters

Query voters information by proposalId

### Parameters

| Name            | Type       | Description | Required   | Notes |
| --------------- | ---------- | ----------- | ---------- | ----- |
| **proposal_id** | **String** | proposal id | [required] |

### Return type

[**Vec<crate::models::GovProposalsProposalIdVotesGetResponseInner>**](_gov_proposals__proposalId__votes_get_response_inner.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)

## gov_proposals_proposal_id_votes_post

> crate::models::TxsHashGetResponseTx gov_proposals_proposal_id_votes_post(proposal_id, gov_proposals_proposal_id_votes_post_request)
> Vote a proposal

Send transaction to vote a proposal

### Parameters

| Name                                             | Type                                                                                    | Description                                                                                        | Required   | Notes |
| ------------------------------------------------ | --------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------- | ---------- | ----- |
| **proposal_id**                                  | **String**                                                                              | proposal id                                                                                        | [required] |
| **gov_proposals_proposal_id_votes_post_request** | [**GovProposalsProposalIdVotesPostRequest**](GovProposalsProposalIdVotesPostRequest.md) | valid value of `\"option\"` field can be `\"yes\"`, `\"no\"`, `\"no_with_veto\"` and `\"abstain\"` | [required] |

### Return type

[**crate::models::TxsHashGetResponseTx**](_txs__hash__get_response_tx.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)

## gov_proposals_proposal_id_votes_voter_get

> crate::models::GovProposalsProposalIdVotesGetResponseInner gov_proposals_proposal_id_votes_voter_get(proposal_id, voter)
> Query vote

Query vote information by proposal Id and voter address

### Parameters

| Name            | Type       | Description          | Required   | Notes |
| --------------- | ---------- | -------------------- | ---------- | ----- |
| **proposal_id** | **String** | proposal id          | [required] |
| **voter**       | **String** | Bech32 voter address | [required] |

### Return type

[**crate::models::GovProposalsProposalIdVotesGetResponseInner**](_gov_proposals__proposalId__votes_get_response_inner.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)

## minting_annual_provisions_get

> String minting_annual_provisions_get()
> Current minting annual provisions value

### Parameters

This endpoint does not need any parameter.

### Return type

**String**

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)

## minting_inflation_get

> String minting_inflation_get()
> Current minting inflation value

### Parameters

This endpoint does not need any parameter.

### Return type

**String**

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)

## minting_parameters_get

> crate::models::MintingParametersGetResponse minting_parameters_get()
> Minting module parameters

### Parameters

This endpoint does not need any parameter.

### Return type

[**crate::models::MintingParametersGetResponse**](_minting_parameters_get_response.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)

## node_info_get

> crate::models::NodeInfoGetResponse node_info_get()
> The properties of the connected node

Information about the connected node

### Parameters

This endpoint does not need any parameter.

### Return type

[**crate::models::NodeInfoGetResponse**](_node_info_get_response.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)

## slashing_parameters_get

> crate::models::SlashingParametersGetResponse slashing_parameters_get()
> Get the current slashing parameters

### Parameters

This endpoint does not need any parameter.

### Return type

[**crate::models::SlashingParametersGetResponse**](_slashing_parameters_get_response.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)

## slashing_signing_infos_get

> Vec<crate::models::SlashingSigningInfosGetResponseInner> slashing_signing_infos_get(page, limit)
> Get sign info of given all validators

Get sign info of all validators

### Parameters

| Name      | Type    | Description                      | Required   | Notes |
| --------- | ------- | -------------------------------- | ---------- | ----- |
| **page**  | **i32** | Page number                      | [required] |
| **limit** | **i32** | Maximum number of items per page | [required] |

### Return type

[**Vec<crate::models::SlashingSigningInfosGetResponseInner>**](_slashing_signing_infos_get_response_inner.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)

## slashing_validators_validator_addr_unjail_post

> crate::models::TxsHashGetResponseTx slashing_validators_validator_addr_unjail_post(validator_addr, slashing_validators_validator_addr_unjail_post_request)
> Unjail a jailed validator

Send transaction to unjail a jailed validator

### Parameters

| Name                                                       | Type                                                                                                        | Description              | Required   | Notes |
| ---------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------- | ------------------------ | ---------- | ----- |
| **validator_addr**                                         | **String**                                                                                                  | Bech32 validator address | [required] |
| **slashing_validators_validator_addr_unjail_post_request** | [**SlashingValidatorsValidatorAddrUnjailPostRequest**](SlashingValidatorsValidatorAddrUnjailPostRequest.md) |                          | [required] |

### Return type

[**crate::models::TxsHashGetResponseTx**](_txs__hash__get_response_tx.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)

## staking_delegators_delegator_addr_delegations_get

> Vec<crate::models::StakingDelegatorsDelegatorAddrDelegationsGetResponseInner> staking_delegators_delegator_addr_delegations_get(delegator_addr)
> Get all delegations from a delegator

### Parameters

| Name               | Type       | Description                    | Required   | Notes |
| ------------------ | ---------- | ------------------------------ | ---------- | ----- |
| **delegator_addr** | **String** | Bech32 AccAddress of Delegator | [required] |

### Return type

[**Vec<crate::models::StakingDelegatorsDelegatorAddrDelegationsGetResponseInner>**](_staking_delegators__delegatorAddr__delegations_get_response_inner.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)

## staking_delegators_delegator_addr_delegations_post

> crate::models::TxsHashGetResponseTx staking_delegators_delegator_addr_delegations_post(delegator_addr, staking_delegators_delegator_addr_delegations_post_request)
> Submit delegation

### Parameters

| Name                                                           | Type                                                                                                                        | Description                                       | Required   | Notes |
| -------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------- | ---------- | ----- |
| **delegator_addr**                                             | **String**                                                                                                                  | Bech32 AccAddress of Delegator                    | [required] |
| **staking_delegators_delegator_addr_delegations_post_request** | Option<[**StakingDelegatorsDelegatorAddrDelegationsPostRequest**](StakingDelegatorsDelegatorAddrDelegationsPostRequest.md)> | Delegate an amount of liquid coins to a validator |            |

### Return type

[**crate::models::TxsHashGetResponseTx**](_txs__hash__get_response_tx.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)

## staking_delegators_delegator_addr_delegations_validator_addr_get

> crate::models::StakingDelegatorsDelegatorAddrDelegationsGetResponseInner staking_delegators_delegator_addr_delegations_validator_addr_get(delegator_addr, validator_addr)
> Query the current delegation between a delegator and a validator

### Parameters

| Name               | Type       | Description                         | Required   | Notes |
| ------------------ | ---------- | ----------------------------------- | ---------- | ----- |
| **delegator_addr** | **String** | Bech32 AccAddress of Delegator      | [required] |
| **validator_addr** | **String** | Bech32 OperatorAddress of validator | [required] |

### Return type

[**crate::models::StakingDelegatorsDelegatorAddrDelegationsGetResponseInner**](_staking_delegators__delegatorAddr__delegations_get_response_inner.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)

## staking_delegators_delegator_addr_redelegations_post

> crate::models::TxsHashGetResponseTx staking_delegators_delegator_addr_redelegations_post(delegator_addr, staking_delegators_delegator_addr_redelegations_post_request)
> Submit a redelegation

### Parameters

| Name                                                             | Type                                                                                                                            | Description                    | Required   | Notes |
| ---------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------- | ------------------------------ | ---------- | ----- |
| **delegator_addr**                                               | **String**                                                                                                                      | Bech32 AccAddress of Delegator | [required] |
| **staking_delegators_delegator_addr_redelegations_post_request** | Option<[**StakingDelegatorsDelegatorAddrRedelegationsPostRequest**](StakingDelegatorsDelegatorAddrRedelegationsPostRequest.md)> | The sender and tx information  |            |

### Return type

[**crate::models::TxsHashGetResponseTx**](_txs__hash__get_response_tx.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)

## staking_delegators_delegator_addr_unbonding_delegations_get

> Vec<crate::models::StakingDelegatorsDelegatorAddrUnbondingDelegationsGetResponseInner> staking_delegators_delegator_addr_unbonding_delegations_get(delegator_addr)
> Get all unbonding delegations from a delegator

### Parameters

| Name               | Type       | Description                    | Required   | Notes |
| ------------------ | ---------- | ------------------------------ | ---------- | ----- |
| **delegator_addr** | **String** | Bech32 AccAddress of Delegator | [required] |

### Return type

[**Vec<crate::models::StakingDelegatorsDelegatorAddrUnbondingDelegationsGetResponseInner>**](_staking_delegators__delegatorAddr__unbonding_delegations_get_response_inner.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)

## staking_delegators_delegator_addr_unbonding_delegations_post

> crate::models::TxsHashGetResponseTx staking_delegators_delegator_addr_unbonding_delegations_post(delegator_addr, staking_delegators_delegator_addr_delegations_post_request)
> Submit an unbonding delegation

### Parameters

| Name                                                           | Type                                                                                                                        | Description                                        | Required   | Notes |
| -------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------- | ---------- | ----- |
| **delegator_addr**                                             | **String**                                                                                                                  | Bech32 AccAddress of Delegator                     | [required] |
| **staking_delegators_delegator_addr_delegations_post_request** | Option<[**StakingDelegatorsDelegatorAddrDelegationsPostRequest**](StakingDelegatorsDelegatorAddrDelegationsPostRequest.md)> | Unbond an amount of bonded shares from a validator |            |

### Return type

[**crate::models::TxsHashGetResponseTx**](_txs__hash__get_response_tx.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)

## staking_delegators_delegator_addr_unbonding_delegations_validator_addr_get

> crate::models::StakingDelegatorsDelegatorAddrUnbondingDelegationsValidatorAddrGetResponse staking_delegators_delegator_addr_unbonding_delegations_validator_addr_get(delegator_addr, validator_addr)
> Query all unbonding delegations between a delegator and a validator

### Parameters

| Name               | Type       | Description                         | Required   | Notes |
| ------------------ | ---------- | ----------------------------------- | ---------- | ----- |
| **delegator_addr** | **String** | Bech32 AccAddress of Delegator      | [required] |
| **validator_addr** | **String** | Bech32 OperatorAddress of validator | [required] |

### Return type

[**crate::models::StakingDelegatorsDelegatorAddrUnbondingDelegationsValidatorAddrGetResponse**](_staking_delegators__delegatorAddr__unbonding_delegations__validatorAddr__get_response.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)

## staking_delegators_delegator_addr_validators_get

> Vec<crate::models::StakingDelegatorsDelegatorAddrValidatorsGetResponseInner> staking_delegators_delegator_addr_validators_get(delegator_addr)
> Query all validators that a delegator is bonded to

### Parameters

| Name               | Type       | Description                    | Required   | Notes |
| ------------------ | ---------- | ------------------------------ | ---------- | ----- |
| **delegator_addr** | **String** | Bech32 AccAddress of Delegator | [required] |

### Return type

[**Vec<crate::models::StakingDelegatorsDelegatorAddrValidatorsGetResponseInner>**](_staking_delegators__delegatorAddr__validators_get_response_inner.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)

## staking_delegators_delegator_addr_validators_validator_addr_get

> crate::models::StakingDelegatorsDelegatorAddrValidatorsGetResponseInner staking_delegators_delegator_addr_validators_validator_addr_get(delegator_addr, validator_addr)
> Query a validator that a delegator is bonded to

### Parameters

| Name               | Type       | Description                    | Required   | Notes |
| ------------------ | ---------- | ------------------------------ | ---------- | ----- |
| **delegator_addr** | **String** | Bech32 AccAddress of Delegator | [required] |
| **validator_addr** | **String** | Bech32 ValAddress of Delegator | [required] |

### Return type

[**crate::models::StakingDelegatorsDelegatorAddrValidatorsGetResponseInner**](_staking_delegators__delegatorAddr__validators_get_response_inner.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)

## staking_parameters_get

> crate::models::StakingParametersGetResponse staking_parameters_get()
> Get the current staking parameter values

### Parameters

This endpoint does not need any parameter.

### Return type

[**crate::models::StakingParametersGetResponse**](_staking_parameters_get_response.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)

## staking_pool_get

> crate::models::StakingPoolGetResponse staking_pool_get()
> Get the current state of the staking pool

### Parameters

This endpoint does not need any parameter.

### Return type

[**crate::models::StakingPoolGetResponse**](_staking_pool_get_response.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)

## staking_redelegations_get

> Vec<crate::models::Redelegation> staking_redelegations_get(delegator, validator_from, validator_to)
> Get all redelegations (filter by query params)

### Parameters

| Name               | Type               | Description                       | Required | Notes |
| ------------------ | ------------------ | --------------------------------- | -------- | ----- |
| **delegator**      | Option<**String**> | Bech32 AccAddress of Delegator    |          |
| **validator_from** | Option<**String**> | Bech32 ValAddress of SrcValidator |          |
| **validator_to**   | Option<**String**> | Bech32 ValAddress of DstValidator |          |

### Return type

[**Vec<crate::models::Redelegation>**](Redelegation.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)

## staking_validators_get

> Vec<crate::models::StakingDelegatorsDelegatorAddrValidatorsGetResponseInner> staking_validators_get(status, page, limit)
> Get all validator candidates. By default it returns only the bonded validators.

### Parameters

| Name       | Type               | Description                                                                     | Required | Notes |
| ---------- | ------------------ | ------------------------------------------------------------------------------- | -------- | ----- |
| **status** | Option<**String**> | The validator bond status. Must be either 'bonded', 'unbonded', or 'unbonding'. |          |
| **page**   | Option<**i32**>    | The page number.                                                                |          |
| **limit**  | Option<**i32**>    | The maximum number of items per page.                                           |          |

### Return type

[**Vec<crate::models::StakingDelegatorsDelegatorAddrValidatorsGetResponseInner>**](_staking_delegators__delegatorAddr__validators_get_response_inner.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)

## staking_validators_validator_addr_delegations_get

> Vec<crate::models::StakingDelegatorsDelegatorAddrDelegationsGetResponseInner> staking_validators_validator_addr_delegations_get(validator_addr)
> Get all delegations from a validator

### Parameters

| Name               | Type       | Description                         | Required   | Notes |
| ------------------ | ---------- | ----------------------------------- | ---------- | ----- |
| **validator_addr** | **String** | Bech32 OperatorAddress of validator | [required] |

### Return type

[**Vec<crate::models::StakingDelegatorsDelegatorAddrDelegationsGetResponseInner>**](_staking_delegators__delegatorAddr__delegations_get_response_inner.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)

## staking_validators_validator_addr_get

> crate::models::StakingDelegatorsDelegatorAddrValidatorsGetResponseInner staking_validators_validator_addr_get(validator_addr)
> Query the information from a single validator

### Parameters

| Name               | Type       | Description                         | Required   | Notes |
| ------------------ | ---------- | ----------------------------------- | ---------- | ----- |
| **validator_addr** | **String** | Bech32 OperatorAddress of validator | [required] |

### Return type

[**crate::models::StakingDelegatorsDelegatorAddrValidatorsGetResponseInner**](_staking_delegators__delegatorAddr__validators_get_response_inner.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)

## staking_validators_validator_addr_unbonding_delegations_get

> Vec<crate::models::StakingDelegatorsDelegatorAddrUnbondingDelegationsGetResponseInner> staking_validators_validator_addr_unbonding_delegations_get(validator_addr)
> Get all unbonding delegations from a validator

### Parameters

| Name               | Type       | Description                         | Required   | Notes |
| ------------------ | ---------- | ----------------------------------- | ---------- | ----- |
| **validator_addr** | **String** | Bech32 OperatorAddress of validator | [required] |

### Return type

[**Vec<crate::models::StakingDelegatorsDelegatorAddrUnbondingDelegationsGetResponseInner>**](_staking_delegators__delegatorAddr__unbonding_delegations_get_response_inner.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)

## syncing_get

> crate::models::SyncingGetResponse syncing_get()
> Syncing state of node

Get if the node is currently syning with other nodes

### Parameters

This endpoint does not need any parameter.

### Return type

[**crate::models::SyncingGetResponse**](_syncing_get_response.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)

## txs_decode_post

> crate::models::TxsHashGetResponseTx txs_decode_post(txs_decode_post_request)
> Decode a transaction from the Amino wire format

Decode a transaction (signed or not) from base64-encoded Amino serialized bytes to JSON

### Parameters

| Name                        | Type                                                | Description      | Required   | Notes |
| --------------------------- | --------------------------------------------------- | ---------------- | ---------- | ----- |
| **txs_decode_post_request** | [**TxsDecodePostRequest**](TxsDecodePostRequest.md) | The tx to decode | [required] |

### Return type

[**crate::models::TxsHashGetResponseTx**](_txs__hash__get_response_tx.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)

## txs_encode_post

> crate::models::TxsEncodePostResponse txs_encode_post(txs_encode_post_request)
> Encode a transaction to the Amino wire format

Encode a transaction (signed or not) from JSON to base64-encoded Amino serialized bytes

### Parameters

| Name                        | Type                                                | Description      | Required   | Notes |
| --------------------------- | --------------------------------------------------- | ---------------- | ---------- | ----- |
| **txs_encode_post_request** | [**TxsEncodePostRequest**](TxsEncodePostRequest.md) | The tx to encode | [required] |

### Return type

[**crate::models::TxsEncodePostResponse**](_txs_encode_post_response.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)

## txs_get

> crate::models::TxsGetResponse txs_get(message_period_action, message_period_sender, page, limit, tx_period_minheight, tx_period_maxheight)
> Search transactions

Search transactions by events.

### Parameters

| Name                      | Type               | Description                                                                                                                                                                                                                                         | Required | Notes |
| ------------------------- | ------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------- | ----- |
| **message_period_action** | Option<**String**> | transaction events such as 'message.action=send' which results in the following endpoint: 'GET /txs?message.action=send'. note that each module documents its own events. look for xx_events.md in the corresponding cosmos-sdk/docs/spec directory |          |
| **message_period_sender** | Option<**String**> | transaction tags with sender: 'GET /txs?message.action=send&message.sender=cosmos16xyempempp92x9hyzz9wrgf94r6j9h5f06pxxv'                                                                                                                           |          |
| **page**                  | Option<**i32**>    | Page number                                                                                                                                                                                                                                         |          |
| **limit**                 | Option<**i32**>    | Maximum number of items per page                                                                                                                                                                                                                    |          |
| **tx_period_minheight**   | Option<**i32**>    | transactions on blocks with height greater or equal this value                                                                                                                                                                                      |          |
| **tx_period_maxheight**   | Option<**i32**>    | transactions on blocks with height less than or equal this value                                                                                                                                                                                    |          |

### Return type

[**crate::models::TxsGetResponse**](_txs_get_response.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)

## txs_hash_get

> crate::models::TxsHashGetResponse txs_hash_get(hash)
> Get a Tx by hash

Retrieve a transaction using its hash.

### Parameters

| Name     | Type       | Description | Required   | Notes |
| -------- | ---------- | ----------- | ---------- | ----- |
| **hash** | **String** | Tx hash     | [required] |

### Return type

[**crate::models::TxsHashGetResponse**](_txs__hash__get_response.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)

## txs_post

> crate::models::TxsPostResponse txs_post(txs_post_request)
> Broadcast a signed tx

Broadcast a signed tx to a full node

### Parameters

| Name                 | Type                                    | Description                                                                                                                                                                   | Required   | Notes |
| -------------------- | --------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------- | ----- |
| **txs_post_request** | [**TxsPostRequest**](TxsPostRequest.md) | The tx must be a signed StdTx. The supported broadcast modes include `\"block\"`(return after tx commit), `\"sync\"`(return afer CheckTx) and `\"async\"`(return right away). | [required] |

### Return type

[**crate::models::TxsPostResponse**](_txs_post_response.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)

## validatorsets_height_get

> crate::models::ValidatorsetsLatestGetResponse validatorsets_height_get(height)
> Get a validator set a certain height

### Parameters

| Name       | Type    | Description  | Required   | Notes |
| ---------- | ------- | ------------ | ---------- | ----- |
| **height** | **f32** | Block height | [required] |

### Return type

[**crate::models::ValidatorsetsLatestGetResponse**](_validatorsets_latest_get_response.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)

## validatorsets_latest_get

> crate::models::ValidatorsetsLatestGetResponse validatorsets_latest_get()
> Get the latest validator set

### Parameters

This endpoint does not need any parameter.

### Return type

[**crate::models::ValidatorsetsLatestGetResponse**](_validatorsets_latest_get_response.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)

## wasm_code_code_id_contracts_get

> crate::models::WasmCodeCodeIdContractsGetResponse wasm_code_code_id_contracts_get(code_id)
> Get info about all contracts deployed with a code ID

### Parameters

| Name        | Type    | Description               | Required   | Notes |
| ----------- | ------- | ------------------------- | ---------- | ----- |
| **code_id** | **f32** | code ID you want to query | [required] |

### Return type

[**crate::models::WasmCodeCodeIdContractsGetResponse**](_wasm_code__codeID__contracts_get_response.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)

## wasm_code_code_id_get

> crate::models::WasmCodeCodeIdGetResponse wasm_code_code_id_get(code_id)
> Get code info of the code ID

### Parameters

| Name        | Type    | Description               | Required   | Notes |
| ----------- | ------- | ------------------------- | ---------- | ----- |
| **code_id** | **f32** | code ID you want to query | [required] |

### Return type

[**crate::models::WasmCodeCodeIdGetResponse**](_wasm_code__codeID__get_response.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)

## wasm_code_code_id_hash_get

> crate::models::WasmCodeCodeIdHashGetResponse wasm_code_code_id_hash_get(code_id)
> Get code ID data hash

### Parameters

| Name        | Type    | Description               | Required   | Notes |
| ----------- | ------- | ------------------------- | ---------- | ----- |
| **code_id** | **f32** | code ID you want to query | [required] |

### Return type

[**crate::models::WasmCodeCodeIdHashGetResponse**](_wasm_code__codeID__hash_get_response.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)

## wasm_code_code_id_post

> crate::models::TxsHashGetResponseTx wasm_code_code_id_post(code_id, wasm_code_code_id_post_request)
> Instantiate wasm contract message

### Parameters

| Name                               | Type                                                                  | Description                     | Required   | Notes |
| ---------------------------------- | --------------------------------------------------------------------- | ------------------------------- | ---------- | ----- |
| **code_id**                        | **f32**                                                               | code ID you want to instantiate | [required] |
| **wasm_code_code_id_post_request** | Option<[**WasmCodeCodeIdPostRequest**](WasmCodeCodeIdPostRequest.md)> |                                 |            |

### Return type

[**crate::models::TxsHashGetResponseTx**](_txs__hash__get_response_tx.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)

## wasm_code_get

> crate::models::WasmCodeGetResponse wasm_code_get()
> List code info

### Parameters

This endpoint does not need any parameter.

### Return type

[**crate::models::WasmCodeGetResponse**](_wasm_code_get_response.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)

## wasm_code_post

> crate::models::TxsHashGetResponseTx wasm_code_post(wasm_code_post_request)
> Generate wasm store code message

### Parameters

| Name                       | Type                                                      | Description | Required | Notes |
| -------------------------- | --------------------------------------------------------- | ----------- | -------- | ----- |
| **wasm_code_post_request** | Option<[**WasmCodePostRequest**](WasmCodePostRequest.md)> |             |          |

### Return type

[**crate::models::TxsHashGetResponseTx**](_txs__hash__get_response_tx.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)

## wasm_contract_contract_address_code_hash_get

> crate::models::WasmContractContractAddressCodeHashGetResponse wasm_contract_contract_address_code_hash_get(contract_address, query_msg)
> Get stored contract-hash information

### Parameters

| Name                 | Type       | Description                         | Required   | Notes |
| -------------------- | ---------- | ----------------------------------- | ---------- | ----- |
| **contract_address** | **String** | contract address you want to lookup | [required] |
| **query_msg**        | **String** | json formatted query msg            | [required] |

### Return type

[**crate::models::WasmContractContractAddressCodeHashGetResponse**](_wasm_contract__contractAddress__code_hash_get_response.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)

## wasm_contract_contract_address_post

> crate::models::TxsHashGetResponseTx wasm_contract_contract_address_post(contract_address, wasm_contract_contract_address_post_request)
> Execute wasm contract message

### Parameters

| Name                                            | Type                                                                                            | Description                          | Required   | Notes |
| ----------------------------------------------- | ----------------------------------------------------------------------------------------------- | ------------------------------------ | ---------- | ----- |
| **contract_address**                            | **String**                                                                                      | contract address you want to execute | [required] |
| **wasm_contract_contract_address_post_request** | Option<[**WasmContractContractAddressPostRequest**](WasmContractContractAddressPostRequest.md)> |                                      |            |

### Return type

[**crate::models::TxsHashGetResponseTx**](_txs__hash__get_response_tx.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)

## wasm_contract_contract_address_query_query_get

> crate::models::WasmContractContractAddressQueryQueryGetResponse wasm_contract_contract_address_query_query_get(contract_address, query, encoding)
> Get stored information with store key

### Parameters

| Name                 | Type               | Description                                     | Required   | Notes |
| -------------------- | ------------------ | ----------------------------------------------- | ---------- | ----- |
| **contract_address** | **String**         | contract address you want to lookup             | [required] |
| **query**            | **String**         | hex encoded data for the query                  | [required] |
| **encoding**         | Option<**String**> | encoding of the query data (only hex supported) |            |

### Return type

[**crate::models::WasmContractContractAddressQueryQueryGetResponse**](_wasm_contract__contractAddress__query__query__get_response.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)
