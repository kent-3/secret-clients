# \GrpcGatewayApi

All URIs are relative to *http://localhost*

Method | HTTP request | Description
------------- | ------------- | -------------
[**account**](GrpcGatewayApi.md#account) | **GET** /cosmos/auth/v1beta1/accounts/{address} | Account returns account details based on address.
[**accounts**](GrpcGatewayApi.md#accounts) | **GET** /cosmos/auth/v1beta1/accounts | Accounts returns all the existing accounts
[**address_by_label**](GrpcGatewayApi.md#address_by_label) | **GET** /compute/v1beta1/contract_address/{label} | Query contract address by label
[**all_balances**](GrpcGatewayApi.md#all_balances) | **GET** /cosmos/bank/v1beta1/balances/{address} | AllBalances queries the balance of all coins for a single account.
[**all_evidence**](GrpcGatewayApi.md#all_evidence) | **GET** /cosmos/evidence/v1beta1/evidence | AllEvidence queries all evidence.
[**allowance**](GrpcGatewayApi.md#allowance) | **GET** /cosmos/feegrant/v1beta1/allowance/{granter}/{grantee} | Allowance returns fee granted to the grantee by the granter.
[**allowances**](GrpcGatewayApi.md#allowances) | **GET** /cosmos/feegrant/v1beta1/allowances/{grantee} | Allowances returns all the grants for address.
[**allowances_by_granter**](GrpcGatewayApi.md#allowances_by_granter) | **GET** /cosmos/feegrant/v1beta1/issued/{granter} | AllowancesByGranter returns all the grants given by an address Since v0.46
[**annual_provisions**](GrpcGatewayApi.md#annual_provisions) | **GET** /cosmos/mint/v1beta1/annual_provisions | AnnualProvisions current minting annual provisions value.
[**applied_plan**](GrpcGatewayApi.md#applied_plan) | **GET** /cosmos/upgrade/v1beta1/applied_plan/{name} | AppliedPlan queries a previously applied upgrade plan by its name.
[**auth_params**](GrpcGatewayApi.md#auth_params) | **GET** /cosmos/auth/v1beta1/params | Params queries all parameters.
[**balance**](GrpcGatewayApi.md#balance) | **GET** /cosmos/bank/v1beta1/balances/{address}/by_denom | Balance queries the balance of a single coin for a single account.
[**bank_params**](GrpcGatewayApi.md#bank_params) | **GET** /cosmos/bank/v1beta1/params | Params queries the parameters of x/bank module.
[**broadcast_tx**](GrpcGatewayApi.md#broadcast_tx) | **POST** /cosmos/tx/v1beta1/txs | BroadcastTx broadcast transaction.
[**channel**](GrpcGatewayApi.md#channel) | **GET** /ibc/core/channel/v1/channels/{channel_id}/ports/{port_id} | Channel queries an IBC Channel.
[**channel_client_state**](GrpcGatewayApi.md#channel_client_state) | **GET** /ibc/core/channel/v1/channels/{channel_id}/ports/{port_id}/client_state | ChannelClientState queries for the client state for the channel associated with the provided channel identifiers.
[**channel_consensus_state**](GrpcGatewayApi.md#channel_consensus_state) | **GET** /ibc/core/channel/v1/channels/{channel_id}/ports/{port_id}/consensus_state/revision/{revision_number}/height/{revision_height} | ChannelConsensusState queries for the consensus state for the channel associated with the provided channel identifiers.
[**channels**](GrpcGatewayApi.md#channels) | **GET** /ibc/core/channel/v1/channels | Channels queries all the IBC channels of a chain.
[**client_connections**](GrpcGatewayApi.md#client_connections) | **GET** /ibc/core/connection/v1/client_connections/{client_id} | ClientConnections queries the connection paths associated with a client state.
[**client_params**](GrpcGatewayApi.md#client_params) | **GET** /ibc/client/v1/params | ClientParams queries all parameters of the ibc client.
[**client_state**](GrpcGatewayApi.md#client_state) | **GET** /ibc/core/client/v1/client_states/{client_id} | ClientState queries an IBC light client.
[**client_states**](GrpcGatewayApi.md#client_states) | **GET** /ibc/core/client/v1/client_states | ClientStates queries all the IBC light clients of a chain.
[**client_status**](GrpcGatewayApi.md#client_status) | **GET** /ibc/core/client/v1/client_status/{client_id} | Status queries the status of an IBC client.
[**code**](GrpcGatewayApi.md#code) | **GET** /compute/v1beta1/code/{code_id} | Query a specific contract code by id
[**code_hash_by_code_id**](GrpcGatewayApi.md#code_hash_by_code_id) | **GET** /compute/v1beta1/code_hash/by_code_id/{code_id} | Query code hash by code id
[**code_hash_by_contract_address**](GrpcGatewayApi.md#code_hash_by_contract_address) | **GET** /compute/v1beta1/code_hash/by_contract_address/{contract_address} | Query code hash by contract address
[**codes**](GrpcGatewayApi.md#codes) | **GET** /compute/v1beta1/codes | Query all contract codes on-chain
[**community_pool**](GrpcGatewayApi.md#community_pool) | **GET** /cosmos/distribution/v1beta1/community_pool | CommunityPool queries the community pool coins.
[**config**](GrpcGatewayApi.md#config) | **GET** /cosmos/base/node/v1beta1/config | Config queries for the operator configuration.
[**connection**](GrpcGatewayApi.md#connection) | **GET** /ibc/core/connection/v1/connections/{connection_id} | Connection queries an IBC connection end.
[**connection_channels**](GrpcGatewayApi.md#connection_channels) | **GET** /ibc/core/channel/v1/connections/{connection}/channels | ConnectionChannels queries all the channels associated with a connection end.
[**connection_client_state**](GrpcGatewayApi.md#connection_client_state) | **GET** /ibc/core/connection/v1/connections/{connection_id}/client_state | ConnectionClientState queries the client state associated with the connection.
[**connection_consensus_state**](GrpcGatewayApi.md#connection_consensus_state) | **GET** /ibc/core/connection/v1/connections/{connection_id}/consensus_state/revision/{revision_number}/height/{revision_height} | ConnectionConsensusState queries the consensus state associated with the connection.
[**connections**](GrpcGatewayApi.md#connections) | **GET** /ibc/core/connection/v1/connections | Connections queries all the IBC connections of a chain.
[**consensus_state**](GrpcGatewayApi.md#consensus_state) | **GET** /ibc/core/client/v1/consensus_states/{client_id}/revision/{revision_number}/height/{revision_height} | ConsensusState queries a consensus state associated with a client state at a given height.
[**consensus_state_heights**](GrpcGatewayApi.md#consensus_state_heights) | **GET** /ibc/core/client/v1/consensus_states/{client_id}/heights | ConsensusStateHeights queries the height of every consensus states associated with a given client.
[**consensus_states**](GrpcGatewayApi.md#consensus_states) | **GET** /ibc/core/client/v1/consensus_states/{client_id} | ConsensusStates queries all the consensus state associated with a given client.
[**contract_history**](GrpcGatewayApi.md#contract_history) | **GET** /compute/v1beta1/contract_history/{contract_address} | ContractHistory gets the contract code history
[**contract_info**](GrpcGatewayApi.md#contract_info) | **GET** /compute/v1beta1/info/{contract_address} | Query contract info by address
[**contracts_by_code_id**](GrpcGatewayApi.md#contracts_by_code_id) | **GET** /compute/v1beta1/contracts/{code_id} | Query code info by id
[**controller_params**](GrpcGatewayApi.md#controller_params) | **GET** /ibc/apps/interchain_accounts/controller/v1/params | Params queries all parameters of the ICA controller submodule.
[**counterparty_payee**](GrpcGatewayApi.md#counterparty_payee) | **GET** /ibc/apps/fee/v1/channels/{channel_id}/relayers/{relayer}/counterparty_payee | CounterpartyPayee returns the registered counterparty payee for forward relaying
[**current_plan**](GrpcGatewayApi.md#current_plan) | **GET** /cosmos/upgrade/v1beta1/current_plan | CurrentPlan queries the current upgrade plan.
[**delegation**](GrpcGatewayApi.md#delegation) | **GET** /cosmos/staking/v1beta1/validators/{validator_addr}/delegations/{delegator_addr} | Delegation queries delegate info for given validator delegator pair.
[**delegation_rewards**](GrpcGatewayApi.md#delegation_rewards) | **GET** /cosmos/distribution/v1beta1/delegators/{delegator_address}/rewards/{validator_address} | DelegationRewards queries the total rewards accrued by a delegation.
[**delegation_total_rewards**](GrpcGatewayApi.md#delegation_total_rewards) | **GET** /cosmos/distribution/v1beta1/delegators/{delegator_address}/rewards | DelegationTotalRewards queries the total rewards accrued by a each validator.
[**delegator_delegations**](GrpcGatewayApi.md#delegator_delegations) | **GET** /cosmos/staking/v1beta1/delegations/{delegator_addr} | DelegatorDelegations queries all delegations of a given delegator address.
[**delegator_unbonding_delegations**](GrpcGatewayApi.md#delegator_unbonding_delegations) | **GET** /cosmos/staking/v1beta1/delegators/{delegator_addr}/unbonding_delegations | DelegatorUnbondingDelegations queries all unbonding delegations of a given delegator address.
[**delegator_validator**](GrpcGatewayApi.md#delegator_validator) | **GET** /cosmos/staking/v1beta1/delegators/{delegator_addr}/validators/{validator_addr} | DelegatorValidator queries validator info for given delegator validator pair.
[**delegator_validators**](GrpcGatewayApi.md#delegator_validators) | **GET** /cosmos/distribution/v1beta1/delegators/{delegator_address}/validators | DelegatorValidators queries the validators of a delegator.
[**delegator_validators_info**](GrpcGatewayApi.md#delegator_validators_info) | **GET** /cosmos/staking/v1beta1/delegators/{delegator_addr}/validators | DelegatorValidatorsInfo queries all validators info for given delegator address.
[**delegator_withdraw_address**](GrpcGatewayApi.md#delegator_withdraw_address) | **GET** /cosmos/distribution/v1beta1/delegators/{delegator_address}/withdraw_address | DelegatorWithdrawAddress queries withdraw address of a delegator.
[**denom_hash**](GrpcGatewayApi.md#denom_hash) | **GET** /ibc/apps/transfer/v1/denom_hashes/{trace} | DenomHash queries a denomination hash information.
[**denom_metadata**](GrpcGatewayApi.md#denom_metadata) | **GET** /cosmos/bank/v1beta1/denoms_metadata/{denom} | DenomsMetadata queries the client metadata of a given coin denomination.
[**denom_trace**](GrpcGatewayApi.md#denom_trace) | **GET** /ibc/apps/transfer/v1/denom_traces/{hash} | DenomTrace queries a denomination trace information.
[**denom_traces**](GrpcGatewayApi.md#denom_traces) | **GET** /ibc/apps/transfer/v1/denom_traces | DenomTraces queries all denomination traces.
[**denoms_metadata**](GrpcGatewayApi.md#denoms_metadata) | **GET** /cosmos/bank/v1beta1/denoms_metadata | DenomsMetadata queries the client metadata for all registered coin denominations.
[**deposit**](GrpcGatewayApi.md#deposit) | **GET** /cosmos/gov/v1beta1/proposals/{proposal_id}/deposits/{depositor} | Deposit queries single deposit information based proposalID, depositAddr.
[**deposits**](GrpcGatewayApi.md#deposits) | **GET** /cosmos/gov/v1beta1/proposals/{proposal_id}/deposits | Deposits queries all deposits of a single proposal.
[**distribution_params**](GrpcGatewayApi.md#distribution_params) | **GET** /cosmos/distribution/v1beta1/params | Params queries params of the distribution module.
[**emergency_button_params**](GrpcGatewayApi.md#emergency_button_params) | **GET** /emergencybutton/v1beta1/params | Params defines a gRPC query method that returns the emergencybutton module's parameters.
[**encrypted_seed**](GrpcGatewayApi.md#encrypted_seed) | **GET** /registration/v1beta1/encrypted-seed/{pub_key} | Returns the encrypted seed for a registered node by public key
[**escrow_address**](GrpcGatewayApi.md#escrow_address) | **GET** /ibc/apps/transfer/v1/channels/{channel_id}/ports/{port_id}/escrow_address | EscrowAddress returns the escrow address for a particular port and channel id.
[**evidence**](GrpcGatewayApi.md#evidence) | **GET** /cosmos/evidence/v1beta1/evidence/{evidence_hash} | Evidence queries evidence based on evidence hash.
[**fee_enabled_channel**](GrpcGatewayApi.md#fee_enabled_channel) | **GET** /ibc/apps/fee/v1/channels/{channel_id}/ports/{port_id}/fee_enabled | FeeEnabledChannel returns true if the provided port and channel identifiers belong to a fee enabled channel
[**fee_enabled_channels**](GrpcGatewayApi.md#fee_enabled_channels) | **GET** /ibc/apps/fee/v1/fee_enabled | FeeEnabledChannels returns a list of all fee enabled channels
[**foundation_tax**](GrpcGatewayApi.md#foundation_tax) | **GET** /cosmos/distribution/v1beta1/foundation_tax | DelegatorWithdrawAddress queries withdraw address of a delegator.
[**get_block_by_height**](GrpcGatewayApi.md#get_block_by_height) | **GET** /cosmos/base/tendermint/v1beta1/blocks/{height} | GetBlockByHeight queries block for given height.
[**get_block_with_txs**](GrpcGatewayApi.md#get_block_with_txs) | **GET** /cosmos/tx/v1beta1/txs/block/{height} | GetBlockWithTxs fetches a block with decoded txs.
[**get_latest_block**](GrpcGatewayApi.md#get_latest_block) | **GET** /cosmos/base/tendermint/v1beta1/blocks/latest | GetLatestBlock returns the latest block.
[**get_latest_validator_set**](GrpcGatewayApi.md#get_latest_validator_set) | **GET** /cosmos/base/tendermint/v1beta1/validatorsets/latest | GetLatestValidatorSet queries latest validator-set.
[**get_node_info**](GrpcGatewayApi.md#get_node_info) | **GET** /cosmos/base/tendermint/v1beta1/node_info | GetNodeInfo queries the current node info.
[**get_syncing**](GrpcGatewayApi.md#get_syncing) | **GET** /cosmos/base/tendermint/v1beta1/syncing | GetSyncing queries node syncing.
[**get_tx**](GrpcGatewayApi.md#get_tx) | **GET** /cosmos/tx/v1beta1/txs/{hash} | GetTx fetches a tx by hash.
[**get_txs_event**](GrpcGatewayApi.md#get_txs_event) | **GET** /cosmos/tx/v1beta1/txs | GetTxsEvent fetches txs by event.
[**get_validator_set_by_height**](GrpcGatewayApi.md#get_validator_set_by_height) | **GET** /cosmos/base/tendermint/v1beta1/validatorsets/{height} | GetValidatorSetByHeight queries validator-set at a given height.
[**gov_params**](GrpcGatewayApi.md#gov_params) | **GET** /cosmos/gov/v1beta1/params/{params_type} | Params queries all parameters of the gov module.
[**grantee_grants**](GrpcGatewayApi.md#grantee_grants) | **GET** /cosmos/authz/v1beta1/grants/grantee/{grantee} | GranteeGrants returns a list of `GrantAuthorization` by grantee.
[**granter_grants**](GrpcGatewayApi.md#granter_grants) | **GET** /cosmos/authz/v1beta1/grants/granter/{granter} | GranterGrants returns list of `GrantAuthorization`, granted by granter.
[**grants**](GrpcGatewayApi.md#grants) | **GET** /cosmos/authz/v1beta1/grants | Returns list of `Authorization`, granted to the grantee by the granter.
[**historical_info**](GrpcGatewayApi.md#historical_info) | **GET** /cosmos/staking/v1beta1/historical_info/{height} | HistoricalInfo queries the historical info for given height.
[**host_params**](GrpcGatewayApi.md#host_params) | **GET** /ibc/apps/interchain_accounts/host/v1/params | Params queries all parameters of the ICA host submodule.
[**incentivized_packet**](GrpcGatewayApi.md#incentivized_packet) | **GET** /ibc/apps/fee/v1/channels/{packet_id.channel_id}/ports/{packet_id.port_id}/sequences/{packet_id.sequence}/incentivized_packet | IncentivizedPacket returns all packet fees for a packet given its identifier
[**incentivized_packets**](GrpcGatewayApi.md#incentivized_packets) | **GET** /ibc/apps/fee/v1/incentivized_packets | IncentivizedPackets returns all incentivized packets and their associated fees
[**incentivized_packets_for_channel**](GrpcGatewayApi.md#incentivized_packets_for_channel) | **GET** /ibc/apps/fee/v1/channels/{channel_id}/ports/{port_id}/incentivized_packets | Gets all incentivized packets for a specific channel
[**inflation**](GrpcGatewayApi.md#inflation) | **GET** /cosmos/mint/v1beta1/inflation | Inflation returns the current minting inflation value.
[**interchain_account**](GrpcGatewayApi.md#interchain_account) | **GET** /ibc/apps/interchain_accounts/controller/v1/owners/{owner}/connections/{connection_id} | InterchainAccount returns the interchain account address for a given owner address on a given connection
[**interchain_account_from_address**](GrpcGatewayApi.md#interchain_account_from_address) | **GET** /mauth/interchain_account/owner/{owner}/connection/{connection_id} | QueryInterchainAccountFromAddress returns the interchain account for given owner address on a given connection pair
[**label_by_address**](GrpcGatewayApi.md#label_by_address) | **GET** /compute/v1beta1/label/{contract_address} | Query contract label by address
[**mint_params**](GrpcGatewayApi.md#mint_params) | **GET** /cosmos/mint/v1beta1/params | Params returns the total set of minting parameters.
[**module_account_by_name**](GrpcGatewayApi.md#module_account_by_name) | **GET** /cosmos/auth/v1beta1/module_accounts/{name} | ModuleAccountByName returns the module account info by module name
[**module_versions**](GrpcGatewayApi.md#module_versions) | **GET** /cosmos/upgrade/v1beta1/module_versions | ModuleVersions queries the list of module versions from state.
[**next_sequence_receive**](GrpcGatewayApi.md#next_sequence_receive) | **GET** /ibc/core/channel/v1/channels/{channel_id}/ports/{port_id}/next_sequence | NextSequenceReceive returns the next receive sequence for a given channel.
[**packet_acknowledgement**](GrpcGatewayApi.md#packet_acknowledgement) | **GET** /ibc/core/channel/v1/channels/{channel_id}/ports/{port_id}/packet_acks/{sequence} | PacketAcknowledgement queries a stored packet acknowledgement hash.
[**packet_acknowledgements**](GrpcGatewayApi.md#packet_acknowledgements) | **GET** /ibc/core/channel/v1/channels/{channel_id}/ports/{port_id}/packet_acknowledgements | PacketAcknowledgements returns all the packet acknowledgements associated with a channel.
[**packet_commitment**](GrpcGatewayApi.md#packet_commitment) | **GET** /ibc/core/channel/v1/channels/{channel_id}/ports/{port_id}/packet_commitments/{sequence} | PacketCommitment queries a stored packet commitment hash.
[**packet_commitments**](GrpcGatewayApi.md#packet_commitments) | **GET** /ibc/core/channel/v1/channels/{channel_id}/ports/{port_id}/packet_commitments | PacketCommitments returns all the packet commitments hashes associated with a channel.
[**packet_receipt**](GrpcGatewayApi.md#packet_receipt) | **GET** /ibc/core/channel/v1/channels/{channel_id}/ports/{port_id}/packet_receipts/{sequence} | PacketReceipt queries if a given packet sequence has been received on the queried chain
[**params**](GrpcGatewayApi.md#params) | **GET** /cosmos/params/v1beta1/params | Params queries a specific parameter of a module, given its subspace and key.
[**payee**](GrpcGatewayApi.md#payee) | **GET** /ibc/apps/fee/v1/channels/{channel_id}/relayers/{relayer}/payee | Payee returns the registered payee address for a specific channel given the relayer address
[**pool**](GrpcGatewayApi.md#pool) | **GET** /cosmos/staking/v1beta1/pool | Pool queries the pool info.
[**proposal**](GrpcGatewayApi.md#proposal) | **GET** /cosmos/gov/v1beta1/proposals/{proposal_id} | Proposal queries proposal details based on ProposalID.
[**proposals**](GrpcGatewayApi.md#proposals) | **GET** /cosmos/gov/v1beta1/proposals | Proposals queries all proposals based on given status.
[**query_secret_contract**](GrpcGatewayApi.md#query_secret_contract) | **GET** /compute/v1beta1/query/{contract_address} | Query secret contract
[**redelegations**](GrpcGatewayApi.md#redelegations) | **GET** /cosmos/staking/v1beta1/delegators/{delegator_addr}/redelegations | Redelegations queries redelegations of given address.
[**registration_key**](GrpcGatewayApi.md#registration_key) | **GET** /registration/v1beta1/registration-key | Returns the key used for registration
[**restake_threshold**](GrpcGatewayApi.md#restake_threshold) | **GET** /cosmos/distribution/v1beta1/restake_threshold | RestakeThreshold queries the community pool coins.
[**restaking_entries**](GrpcGatewayApi.md#restaking_entries) | **GET** /cosmos/distribution/v1beta1/restake_entries | RestakeThreshold queries the community pool coins.
[**router_params**](GrpcGatewayApi.md#router_params) | **GET** /ibc/apps/router/v1/params | Params queries all parameters of the router module.
[**signing_info**](GrpcGatewayApi.md#signing_info) | **GET** /cosmos/slashing/v1beta1/signing_infos/{cons_address} | SigningInfo queries the signing info of given cons address
[**signing_infos**](GrpcGatewayApi.md#signing_infos) | **GET** /cosmos/slashing/v1beta1/signing_infos | SigningInfos queries signing info of all validators
[**simulate**](GrpcGatewayApi.md#simulate) | **POST** /cosmos/tx/v1beta1/simulate | Simulate simulates executing a transaction for estimating gas usage.
[**slashing_params**](GrpcGatewayApi.md#slashing_params) | **GET** /cosmos/slashing/v1beta1/params | Params queries the parameters of slashing module
[**spendable_balances**](GrpcGatewayApi.md#spendable_balances) | **GET** /cosmos/bank/v1beta1/spendable_balances/{address} | SpendableBalances queries the spenable balance of all coins for a single account.
[**staking_params**](GrpcGatewayApi.md#staking_params) | **GET** /cosmos/staking/v1beta1/params | Parameters queries the staking parameters.
[**supply_of**](GrpcGatewayApi.md#supply_of) | **GET** /cosmos/bank/v1beta1/supply/{denom} | SupplyOf queries the supply of a single coin.
[**tally_result**](GrpcGatewayApi.md#tally_result) | **GET** /cosmos/gov/v1beta1/proposals/{proposal_id}/tally | TallyResult queries the tally of a proposal vote.
[**total_ack_fees**](GrpcGatewayApi.md#total_ack_fees) | **GET** /ibc/apps/fee/v1/channels/{packet_id.channel_id}/ports/{packet_id.port_id}/sequences/{packet_id.sequence}/total_ack_fees | TotalAckFees returns the total acknowledgement fees for a packet given its identifier
[**total_recv_fees**](GrpcGatewayApi.md#total_recv_fees) | **GET** /ibc/apps/fee/v1/channels/{packet_id.channel_id}/ports/{packet_id.port_id}/sequences/{packet_id.sequence}/total_recv_fees | TotalRecvFees returns the total receive fees for a packet given its identifier
[**total_supply**](GrpcGatewayApi.md#total_supply) | **GET** /cosmos/bank/v1beta1/supply | TotalSupply queries the total supply of all coins.
[**total_timeout_fees**](GrpcGatewayApi.md#total_timeout_fees) | **GET** /ibc/apps/fee/v1/channels/{packet_id.channel_id}/ports/{packet_id.port_id}/sequences/{packet_id.sequence}/total_timeout_fees | TotalTimeoutFees returns the total timeout fees for a packet given its identifier
[**transfer_params**](GrpcGatewayApi.md#transfer_params) | **GET** /ibc/apps/transfer/v1/params | Params queries all parameters of the ibc-transfer module.
[**tx_key**](GrpcGatewayApi.md#tx_key) | **GET** /registration/v1beta1/tx-key | Returns the key used for transactions
[**unbonding_delegation**](GrpcGatewayApi.md#unbonding_delegation) | **GET** /cosmos/staking/v1beta1/validators/{validator_addr}/delegations/{delegator_addr}/unbonding_delegation | UnbondingDelegation queries unbonding info for given validator delegator pair.
[**unreceived_acks**](GrpcGatewayApi.md#unreceived_acks) | **GET** /ibc/core/channel/v1/channels/{channel_id}/ports/{port_id}/packet_commitments/{packet_ack_sequences}/unreceived_acks | UnreceivedAcks returns all the unreceived IBC acknowledgements associated with a channel and sequences.
[**unreceived_packets**](GrpcGatewayApi.md#unreceived_packets) | **GET** /ibc/core/channel/v1/channels/{channel_id}/ports/{port_id}/packet_commitments/{packet_commitment_sequences}/unreceived_packets | UnreceivedPackets returns all the unreceived IBC packets associated with a channel and sequences.
[**upgraded_client_state**](GrpcGatewayApi.md#upgraded_client_state) | **GET** /ibc/core/client/v1/upgraded_client_states | UpgradedClientState queries an Upgraded IBC light client.
[**upgraded_consensus_state**](GrpcGatewayApi.md#upgraded_consensus_state) | **GET** /ibc/core/client/v1/upgraded_consensus_states | UpgradedConsensusState queries an Upgraded IBC consensus state.
[**upgraded_consensus_state_last_height**](GrpcGatewayApi.md#upgraded_consensus_state_last_height) | **GET** /cosmos/upgrade/v1beta1/upgraded_consensus_state/{last_height} | UpgradedConsensusState queries the consensus state that will serve as a trusted kernel for the next version of this chain. It will only be stored at the last height of this chain. UpgradedConsensusState RPC not supported with legacy querier This rpc is deprecated now that IBC has its own replacement (https://github.com/cosmos/ibc-go/blob/2c880a22e9f9cc75f62b527ca94aa75ce1106001/proto/ibc/core/client/v1/query.proto#L54)
[**validator**](GrpcGatewayApi.md#validator) | **GET** /cosmos/staking/v1beta1/validators/{validator_addr} | Validator queries validator info for given validator address.
[**validator_commission**](GrpcGatewayApi.md#validator_commission) | **GET** /cosmos/distribution/v1beta1/validators/{validator_address}/commission | ValidatorCommission queries accumulated commission for a validator.
[**validator_delegations**](GrpcGatewayApi.md#validator_delegations) | **GET** /cosmos/staking/v1beta1/validators/{validator_addr}/delegations | ValidatorDelegations queries delegate info for given validator.
[**validator_outstanding_rewards**](GrpcGatewayApi.md#validator_outstanding_rewards) | **GET** /cosmos/distribution/v1beta1/validators/{validator_address}/outstanding_rewards | ValidatorOutstandingRewards queries rewards of a validator address.
[**validator_slashes**](GrpcGatewayApi.md#validator_slashes) | **GET** /cosmos/distribution/v1beta1/validators/{validator_address}/slashes | ValidatorSlashes queries slash events of a validator.
[**validator_unbonding_delegations**](GrpcGatewayApi.md#validator_unbonding_delegations) | **GET** /cosmos/staking/v1beta1/validators/{validator_addr}/unbonding_delegations | ValidatorUnbondingDelegations queries unbonding delegations of a validator.
[**validators**](GrpcGatewayApi.md#validators) | **GET** /cosmos/staking/v1beta1/validators | Validators queries all validators that match the given status.
[**vote**](GrpcGatewayApi.md#vote) | **GET** /cosmos/gov/v1beta1/proposals/{proposal_id}/votes/{voter} | Vote queries voted information based on proposalID, voterAddr.
[**votes**](GrpcGatewayApi.md#votes) | **GET** /cosmos/gov/v1beta1/proposals/{proposal_id}/votes | Votes queries votes of a given proposal.



## account

> crate::models::AccountResponse account(address)
Account returns account details based on address.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**address** | **String** | address defines the address to query for. | [required] |

### Return type

[**crate::models::AccountResponse**](Account_response.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: */*

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)


## accounts

> crate::models::AccountsResponse accounts(pagination_period_key, pagination_period_offset, pagination_period_limit, pagination_period_count_total, pagination_period_reverse)
Accounts returns all the existing accounts

Since: cosmos-sdk 0.43

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**pagination_period_key** | Option<**String**> | key is a value returned in PageResponse.next_key to begin querying the next page most efficiently. Only one of offset or key should be set. |  |
**pagination_period_offset** | Option<**String**> | offset is a numeric offset that can be used when key is unavailable. It is less efficient than using key. Only one of offset or key should be set. |  |
**pagination_period_limit** | Option<**String**> | limit is the total number of results to be returned in the result page. If left empty it will default to a value to be set by each app. |  |
**pagination_period_count_total** | Option<**bool**> | count_total is set to true  to indicate that the result set should include a count of the total number of items available for pagination in UIs. count_total is only respected when offset is used. It is ignored when key is set. |  |
**pagination_period_reverse** | Option<**bool**> | reverse is set to true if results are to be returned in the descending order.  Since: cosmos-sdk 0.43 |  |

### Return type

[**crate::models::AccountsResponse**](Accounts_response.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: */*

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)


## address_by_label

> crate::models::AddressByLabelResponse address_by_label(label)
Query contract address by label

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**label** | **String** |  | [required] |

### Return type

[**crate::models::AddressByLabelResponse**](AddressByLabel_response.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: */*

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)


## all_balances

> crate::models::AllBalancesResponse all_balances(address, pagination_period_key, pagination_period_offset, pagination_period_limit, pagination_period_count_total, pagination_period_reverse)
AllBalances queries the balance of all coins for a single account.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**address** | **String** | address is the address to query balances for. | [required] |
**pagination_period_key** | Option<**String**> | key is a value returned in PageResponse.next_key to begin querying the next page most efficiently. Only one of offset or key should be set. |  |
**pagination_period_offset** | Option<**String**> | offset is a numeric offset that can be used when key is unavailable. It is less efficient than using key. Only one of offset or key should be set. |  |
**pagination_period_limit** | Option<**String**> | limit is the total number of results to be returned in the result page. If left empty it will default to a value to be set by each app. |  |
**pagination_period_count_total** | Option<**bool**> | count_total is set to true  to indicate that the result set should include a count of the total number of items available for pagination in UIs. count_total is only respected when offset is used. It is ignored when key is set. |  |
**pagination_period_reverse** | Option<**bool**> | reverse is set to true if results are to be returned in the descending order.  Since: cosmos-sdk 0.43 |  |

### Return type

[**crate::models::AllBalancesResponse**](AllBalances_response.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: */*

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)


## all_evidence

> crate::models::AllEvidenceResponse all_evidence(pagination_period_key, pagination_period_offset, pagination_period_limit, pagination_period_count_total, pagination_period_reverse)
AllEvidence queries all evidence.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**pagination_period_key** | Option<**String**> | key is a value returned in PageResponse.next_key to begin querying the next page most efficiently. Only one of offset or key should be set. |  |
**pagination_period_offset** | Option<**String**> | offset is a numeric offset that can be used when key is unavailable. It is less efficient than using key. Only one of offset or key should be set. |  |
**pagination_period_limit** | Option<**String**> | limit is the total number of results to be returned in the result page. If left empty it will default to a value to be set by each app. |  |
**pagination_period_count_total** | Option<**bool**> | count_total is set to true  to indicate that the result set should include a count of the total number of items available for pagination in UIs. count_total is only respected when offset is used. It is ignored when key is set. |  |
**pagination_period_reverse** | Option<**bool**> | reverse is set to true if results are to be returned in the descending order.  Since: cosmos-sdk 0.43 |  |

### Return type

[**crate::models::AllEvidenceResponse**](AllEvidence_response.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: */*

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)


## allowance

> crate::models::AllowanceResponse allowance(granter, grantee)
Allowance returns fee granted to the grantee by the granter.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**granter** | **String** | granter is the address of the user granting an allowance of their funds. | [required] |
**grantee** | **String** | grantee is the address of the user being granted an allowance of another user's funds. | [required] |

### Return type

[**crate::models::AllowanceResponse**](Allowance_response.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: */*

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)


## allowances

> crate::models::AllowancesResponse allowances(grantee, pagination_period_key, pagination_period_offset, pagination_period_limit, pagination_period_count_total, pagination_period_reverse)
Allowances returns all the grants for address.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**grantee** | **String** |  | [required] |
**pagination_period_key** | Option<**String**> | key is a value returned in PageResponse.next_key to begin querying the next page most efficiently. Only one of offset or key should be set. |  |
**pagination_period_offset** | Option<**String**> | offset is a numeric offset that can be used when key is unavailable. It is less efficient than using key. Only one of offset or key should be set. |  |
**pagination_period_limit** | Option<**String**> | limit is the total number of results to be returned in the result page. If left empty it will default to a value to be set by each app. |  |
**pagination_period_count_total** | Option<**bool**> | count_total is set to true  to indicate that the result set should include a count of the total number of items available for pagination in UIs. count_total is only respected when offset is used. It is ignored when key is set. |  |
**pagination_period_reverse** | Option<**bool**> | reverse is set to true if results are to be returned in the descending order.  Since: cosmos-sdk 0.43 |  |

### Return type

[**crate::models::AllowancesResponse**](Allowances_response.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: */*

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)


## allowances_by_granter

> crate::models::AllowancesByGranterResponse allowances_by_granter(granter, pagination_period_key, pagination_period_offset, pagination_period_limit, pagination_period_count_total, pagination_period_reverse)
AllowancesByGranter returns all the grants given by an address Since v0.46

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**granter** | **String** |  | [required] |
**pagination_period_key** | Option<**String**> | key is a value returned in PageResponse.next_key to begin querying the next page most efficiently. Only one of offset or key should be set. |  |
**pagination_period_offset** | Option<**String**> | offset is a numeric offset that can be used when key is unavailable. It is less efficient than using key. Only one of offset or key should be set. |  |
**pagination_period_limit** | Option<**String**> | limit is the total number of results to be returned in the result page. If left empty it will default to a value to be set by each app. |  |
**pagination_period_count_total** | Option<**bool**> | count_total is set to true  to indicate that the result set should include a count of the total number of items available for pagination in UIs. count_total is only respected when offset is used. It is ignored when key is set. |  |
**pagination_period_reverse** | Option<**bool**> | reverse is set to true if results are to be returned in the descending order.  Since: cosmos-sdk 0.43 |  |

### Return type

[**crate::models::AllowancesByGranterResponse**](AllowancesByGranter_response.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: */*

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)


## annual_provisions

> crate::models::AnnualProvisionsResponse annual_provisions()
AnnualProvisions current minting annual provisions value.

### Parameters

This endpoint does not need any parameter.

### Return type

[**crate::models::AnnualProvisionsResponse**](AnnualProvisions_response.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: */*

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)


## applied_plan

> crate::models::AppliedPlanResponse applied_plan(name)
AppliedPlan queries a previously applied upgrade plan by its name.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**name** | **String** | name is the name of the applied plan to query for. | [required] |

### Return type

[**crate::models::AppliedPlanResponse**](AppliedPlan_response.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: */*

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)


## auth_params

> crate::models::AuthParamsResponse auth_params()
Params queries all parameters.

### Parameters

This endpoint does not need any parameter.

### Return type

[**crate::models::AuthParamsResponse**](AuthParams_response.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: */*

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)


## balance

> crate::models::BalanceResponse balance(address, denom)
Balance queries the balance of a single coin for a single account.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**address** | **String** | address is the address to query balances for. | [required] |
**denom** | Option<**String**> | denom is the coin denom to query balances for. |  |

### Return type

[**crate::models::BalanceResponse**](Balance_response.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: */*

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)


## bank_params

> crate::models::BankParamsResponse bank_params()
Params queries the parameters of x/bank module.

### Parameters

This endpoint does not need any parameter.

### Return type

[**crate::models::BankParamsResponse**](BankParams_response.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: */*

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)


## broadcast_tx

> crate::models::BroadcastTxResponse broadcast_tx(broadcast_tx_request)
BroadcastTx broadcast transaction.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**broadcast_tx_request** | [**BroadcastTxRequest**](BroadcastTxRequest.md) |  | [required] |

### Return type

[**crate::models::BroadcastTxResponse**](BroadcastTx_response.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: */*

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)


## channel

> crate::models::ChannelResponse channel(channel_id, port_id)
Channel queries an IBC Channel.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**channel_id** | **String** | channel unique identifier | [required] |
**port_id** | **String** | port unique identifier | [required] |

### Return type

[**crate::models::ChannelResponse**](Channel_response.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: */*

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)


## channel_client_state

> crate::models::QueryChannelClientStateResponseIsTheResponseTypeForTheQueryQueryChannelClientStateRpcMethod channel_client_state(channel_id, port_id)
ChannelClientState queries for the client state for the channel associated with the provided channel identifiers.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**channel_id** | **String** | channel unique identifier | [required] |
**port_id** | **String** | port unique identifier | [required] |

### Return type

[**crate::models::QueryChannelClientStateResponseIsTheResponseTypeForTheQueryQueryChannelClientStateRpcMethod**](QueryChannelClientStateResponse_is_the_Response_type_for_the_Query_QueryChannelClientState_RPC_method.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: */*

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)


## channel_consensus_state

> crate::models::QueryChannelClientStateResponseIsTheResponseTypeForTheQueryQueryChannelClientStateRpcMethod1 channel_consensus_state(channel_id, port_id, revision_number, revision_height)
ChannelConsensusState queries for the consensus state for the channel associated with the provided channel identifiers.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**channel_id** | **String** | channel unique identifier | [required] |
**port_id** | **String** | port unique identifier | [required] |
**revision_number** | **String** | revision number of the consensus state | [required] |
**revision_height** | **String** | revision height of the consensus state | [required] |

### Return type

[**crate::models::QueryChannelClientStateResponseIsTheResponseTypeForTheQueryQueryChannelClientStateRpcMethod1**](QueryChannelClientStateResponse_is_the_Response_type_for_the_Query_QueryChannelClientState_RPC_method_1.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: */*

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)


## channels

> crate::models::ChannelsResponse channels(pagination_period_key, pagination_period_offset, pagination_period_limit, pagination_period_count_total, pagination_period_reverse)
Channels queries all the IBC channels of a chain.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**pagination_period_key** | Option<**String**> | key is a value returned in PageResponse.next_key to begin querying the next page most efficiently. Only one of offset or key should be set. |  |
**pagination_period_offset** | Option<**String**> | offset is a numeric offset that can be used when key is unavailable. It is less efficient than using key. Only one of offset or key should be set. |  |
**pagination_period_limit** | Option<**String**> | limit is the total number of results to be returned in the result page. If left empty it will default to a value to be set by each app. |  |
**pagination_period_count_total** | Option<**bool**> | count_total is set to true  to indicate that the result set should include a count of the total number of items available for pagination in UIs. count_total is only respected when offset is used. It is ignored when key is set. |  |
**pagination_period_reverse** | Option<**bool**> | reverse is set to true if results are to be returned in the descending order.  Since: cosmos-sdk 0.43 |  |

### Return type

[**crate::models::ChannelsResponse**](Channels_response.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: */*

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)


## client_connections

> crate::models::QueryClientConnectionsResponseIsTheResponseTypeForTheQueryClientConnectionsRpcMethod client_connections(client_id)
ClientConnections queries the connection paths associated with a client state.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**client_id** | **String** | client identifier associated with a connection | [required] |

### Return type

[**crate::models::QueryClientConnectionsResponseIsTheResponseTypeForTheQueryClientConnectionsRpcMethod**](QueryClientConnectionsResponse_is_the_response_type_for_the_Query_ClientConnections_RPC_method.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: */*

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)


## client_params

> crate::models::ClientParamsResponse client_params()
ClientParams queries all parameters of the ibc client.

### Parameters

This endpoint does not need any parameter.

### Return type

[**crate::models::ClientParamsResponse**](ClientParams_response.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: */*

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)


## client_state

> crate::models::ClientStateResponse client_state(client_id)
ClientState queries an IBC light client.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**client_id** | **String** | client state unique identifier | [required] |

### Return type

[**crate::models::ClientStateResponse**](ClientState_response.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: */*

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)


## client_states

> crate::models::ClientStatesResponse client_states(pagination_period_key, pagination_period_offset, pagination_period_limit, pagination_period_count_total, pagination_period_reverse)
ClientStates queries all the IBC light clients of a chain.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**pagination_period_key** | Option<**String**> | key is a value returned in PageResponse.next_key to begin querying the next page most efficiently. Only one of offset or key should be set. |  |
**pagination_period_offset** | Option<**String**> | offset is a numeric offset that can be used when key is unavailable. It is less efficient than using key. Only one of offset or key should be set. |  |
**pagination_period_limit** | Option<**String**> | limit is the total number of results to be returned in the result page. If left empty it will default to a value to be set by each app. |  |
**pagination_period_count_total** | Option<**bool**> | count_total is set to true  to indicate that the result set should include a count of the total number of items available for pagination in UIs. count_total is only respected when offset is used. It is ignored when key is set. |  |
**pagination_period_reverse** | Option<**bool**> | reverse is set to true if results are to be returned in the descending order.  Since: cosmos-sdk 0.43 |  |

### Return type

[**crate::models::ClientStatesResponse**](ClientStates_response.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: */*

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)


## client_status

> crate::models::ClientStatusResponse client_status(client_id)
Status queries the status of an IBC client.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**client_id** | **String** | client unique identifier | [required] |

### Return type

[**crate::models::ClientStatusResponse**](ClientStatus_response.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: */*

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)


## code

> crate::models::CodeResponse code(code_id)
Query a specific contract code by id

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**code_id** | **String** |  | [required] |

### Return type

[**crate::models::CodeResponse**](Code_response.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: */*

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)


## code_hash_by_code_id

> crate::models::CodeHashByCodeIdResponse code_hash_by_code_id(code_id)
Query code hash by code id

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**code_id** | **String** |  | [required] |

### Return type

[**crate::models::CodeHashByCodeIdResponse**](CodeHashByCodeId_response.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: */*

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)


## code_hash_by_contract_address

> crate::models::CodeHashByCodeIdResponse code_hash_by_contract_address(contract_address)
Query code hash by contract address

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**contract_address** | **String** | address is the bech32 human readable address of the contract | [required] |

### Return type

[**crate::models::CodeHashByCodeIdResponse**](CodeHashByCodeId_response.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: */*

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)


## codes

> crate::models::CodesResponse codes()
Query all contract codes on-chain

### Parameters

This endpoint does not need any parameter.

### Return type

[**crate::models::CodesResponse**](Codes_response.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: */*

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)


## community_pool

> crate::models::CommunityPoolResponse community_pool()
CommunityPool queries the community pool coins.

### Parameters

This endpoint does not need any parameter.

### Return type

[**crate::models::CommunityPoolResponse**](CommunityPool_response.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: */*

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)


## config

> crate::models::ConfigResponse config()
Config queries for the operator configuration.

### Parameters

This endpoint does not need any parameter.

### Return type

[**crate::models::ConfigResponse**](Config_response.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: */*

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)


## connection

> crate::models::ConnectionResponse connection(connection_id)
Connection queries an IBC connection end.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**connection_id** | **String** | connection unique identifier | [required] |

### Return type

[**crate::models::ConnectionResponse**](Connection_response.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: */*

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)


## connection_channels

> crate::models::QueryConnectionChannelsResponseIsTheResponseTypeForTheQueryQueryConnectionChannelsRpcMethod connection_channels(connection, pagination_period_key, pagination_period_offset, pagination_period_limit, pagination_period_count_total, pagination_period_reverse)
ConnectionChannels queries all the channels associated with a connection end.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**connection** | **String** | connection unique identifier | [required] |
**pagination_period_key** | Option<**String**> | key is a value returned in PageResponse.next_key to begin querying the next page most efficiently. Only one of offset or key should be set. |  |
**pagination_period_offset** | Option<**String**> | offset is a numeric offset that can be used when key is unavailable. It is less efficient than using key. Only one of offset or key should be set. |  |
**pagination_period_limit** | Option<**String**> | limit is the total number of results to be returned in the result page. If left empty it will default to a value to be set by each app. |  |
**pagination_period_count_total** | Option<**bool**> | count_total is set to true  to indicate that the result set should include a count of the total number of items available for pagination in UIs. count_total is only respected when offset is used. It is ignored when key is set. |  |
**pagination_period_reverse** | Option<**bool**> | reverse is set to true if results are to be returned in the descending order.  Since: cosmos-sdk 0.43 |  |

### Return type

[**crate::models::QueryConnectionChannelsResponseIsTheResponseTypeForTheQueryQueryConnectionChannelsRpcMethod**](QueryConnectionChannelsResponse_is_the_Response_type_for_the_Query_QueryConnectionChannels_RPC_method.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: */*

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)


## connection_client_state

> crate::models::QueryConnectionClientStateResponseIsTheResponseTypeForTheQueryConnectionClientStateRpcMethod connection_client_state(connection_id)
ConnectionClientState queries the client state associated with the connection.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**connection_id** | **String** | connection identifier | [required] |

### Return type

[**crate::models::QueryConnectionClientStateResponseIsTheResponseTypeForTheQueryConnectionClientStateRpcMethod**](QueryConnectionClientStateResponse_is_the_response_type_for_the_Query_ConnectionClientState_RPC_method.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: */*

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)


## connection_consensus_state

> crate::models::QueryConnectionConsensusStateResponseIsTheResponseTypeForTheQueryConnectionConsensusStateRpcMethod connection_consensus_state(connection_id, revision_number, revision_height)
ConnectionConsensusState queries the consensus state associated with the connection.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**connection_id** | **String** | connection identifier | [required] |
**revision_number** | **String** |  | [required] |
**revision_height** | **String** |  | [required] |

### Return type

[**crate::models::QueryConnectionConsensusStateResponseIsTheResponseTypeForTheQueryConnectionConsensusStateRpcMethod**](QueryConnectionConsensusStateResponse_is_the_response_type_for_the_Query_ConnectionConsensusState_RPC_method.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: */*

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)


## connections

> crate::models::ConnectionsResponse connections(pagination_period_key, pagination_period_offset, pagination_period_limit, pagination_period_count_total, pagination_period_reverse)
Connections queries all the IBC connections of a chain.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**pagination_period_key** | Option<**String**> | key is a value returned in PageResponse.next_key to begin querying the next page most efficiently. Only one of offset or key should be set. |  |
**pagination_period_offset** | Option<**String**> | offset is a numeric offset that can be used when key is unavailable. It is less efficient than using key. Only one of offset or key should be set. |  |
**pagination_period_limit** | Option<**String**> | limit is the total number of results to be returned in the result page. If left empty it will default to a value to be set by each app. |  |
**pagination_period_count_total** | Option<**bool**> | count_total is set to true  to indicate that the result set should include a count of the total number of items available for pagination in UIs. count_total is only respected when offset is used. It is ignored when key is set. |  |
**pagination_period_reverse** | Option<**bool**> | reverse is set to true if results are to be returned in the descending order.  Since: cosmos-sdk 0.43 |  |

### Return type

[**crate::models::ConnectionsResponse**](Connections_response.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: */*

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)


## consensus_state

> crate::models::QueryConsensusStateResponseIsTheResponseTypeForTheQueryConsensusStateRpcMethod consensus_state(client_id, revision_number, revision_height, latest_height)
ConsensusState queries a consensus state associated with a client state at a given height.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**client_id** | **String** | client identifier | [required] |
**revision_number** | **String** | consensus state revision number | [required] |
**revision_height** | **String** | consensus state revision height | [required] |
**latest_height** | Option<**bool**> | latest_height overrrides the height field and queries the latest stored ConsensusState. |  |

### Return type

[**crate::models::QueryConsensusStateResponseIsTheResponseTypeForTheQueryConsensusStateRpcMethod**](QueryConsensusStateResponse_is_the_response_type_for_the_Query_ConsensusState_RPC_method.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: */*

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)


## consensus_state_heights

> crate::models::QueryConsensusStateHeightsResponseIsTheResponseTypeForTheQueryConsensusStateHeightsRpcMethod consensus_state_heights(client_id, pagination_period_key, pagination_period_offset, pagination_period_limit, pagination_period_count_total, pagination_period_reverse)
ConsensusStateHeights queries the height of every consensus states associated with a given client.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**client_id** | **String** | client identifier | [required] |
**pagination_period_key** | Option<**String**> | key is a value returned in PageResponse.next_key to begin querying the next page most efficiently. Only one of offset or key should be set. |  |
**pagination_period_offset** | Option<**String**> | offset is a numeric offset that can be used when key is unavailable. It is less efficient than using key. Only one of offset or key should be set. |  |
**pagination_period_limit** | Option<**String**> | limit is the total number of results to be returned in the result page. If left empty it will default to a value to be set by each app. |  |
**pagination_period_count_total** | Option<**bool**> | count_total is set to true  to indicate that the result set should include a count of the total number of items available for pagination in UIs. count_total is only respected when offset is used. It is ignored when key is set. |  |
**pagination_period_reverse** | Option<**bool**> | reverse is set to true if results are to be returned in the descending order.  Since: cosmos-sdk 0.43 |  |

### Return type

[**crate::models::QueryConsensusStateHeightsResponseIsTheResponseTypeForTheQueryConsensusStateHeightsRpcMethod**](QueryConsensusStateHeightsResponse_is_the_response_type_for_the_Query_ConsensusStateHeights_RPC_method.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: */*

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)


## consensus_states

> crate::models::QueryConsensusStatesResponseIsTheResponseTypeForTheQueryConsensusStatesRpcMethod consensus_states(client_id, pagination_period_key, pagination_period_offset, pagination_period_limit, pagination_period_count_total, pagination_period_reverse)
ConsensusStates queries all the consensus state associated with a given client.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**client_id** | **String** | client identifier | [required] |
**pagination_period_key** | Option<**String**> | key is a value returned in PageResponse.next_key to begin querying the next page most efficiently. Only one of offset or key should be set. |  |
**pagination_period_offset** | Option<**String**> | offset is a numeric offset that can be used when key is unavailable. It is less efficient than using key. Only one of offset or key should be set. |  |
**pagination_period_limit** | Option<**String**> | limit is the total number of results to be returned in the result page. If left empty it will default to a value to be set by each app. |  |
**pagination_period_count_total** | Option<**bool**> | count_total is set to true  to indicate that the result set should include a count of the total number of items available for pagination in UIs. count_total is only respected when offset is used. It is ignored when key is set. |  |
**pagination_period_reverse** | Option<**bool**> | reverse is set to true if results are to be returned in the descending order.  Since: cosmos-sdk 0.43 |  |

### Return type

[**crate::models::QueryConsensusStatesResponseIsTheResponseTypeForTheQueryConsensusStatesRpcMethod**](QueryConsensusStatesResponse_is_the_response_type_for_the_Query_ConsensusStates_RPC_method.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: */*

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)


## contract_history

> crate::models::QueryContractHistoryResponseIsTheResponseTypeForTheQueryContractHistoryRpcMethod contract_history(contract_address)
ContractHistory gets the contract code history

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**contract_address** | **String** | address is the address of the contract to query | [required] |

### Return type

[**crate::models::QueryContractHistoryResponseIsTheResponseTypeForTheQueryContractHistoryRpcMethod**](QueryContractHistoryResponse_is_the_response_type_for_the_Query_ContractHistory_RPC_method.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: */*

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)


## contract_info

> crate::models::QueryContractInfoResponseIsTheResponseTypeForTheQueryContractInfoRpcMethod contract_info(contract_address)
Query contract info by address

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**contract_address** | **String** | address is the bech32 human readable address of the contract | [required] |

### Return type

[**crate::models::QueryContractInfoResponseIsTheResponseTypeForTheQueryContractInfoRpcMethod**](QueryContractInfoResponse_is_the_response_type_for_the_Query_ContractInfo_RPC_method.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: */*

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)


## contracts_by_code_id

> crate::models::ContractsByCodeIdResponse contracts_by_code_id(code_id)
Query code info by id

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**code_id** | **String** |  | [required] |

### Return type

[**crate::models::ContractsByCodeIdResponse**](ContractsByCodeId_response.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: */*

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)


## controller_params

> crate::models::ControllerParamsResponse controller_params()
Params queries all parameters of the ICA controller submodule.

### Parameters

This endpoint does not need any parameter.

### Return type

[**crate::models::ControllerParamsResponse**](ControllerParams_response.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: */*

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)


## counterparty_payee

> crate::models::QueryCounterpartyPayeeResponseDefinesTheResponseTypeForTheCounterpartyPayeeRpc counterparty_payee(channel_id, relayer)
CounterpartyPayee returns the registered counterparty payee for forward relaying

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**channel_id** | **String** | unique channel identifier | [required] |
**relayer** | **String** | the relayer address to which the counterparty is registered | [required] |

### Return type

[**crate::models::QueryCounterpartyPayeeResponseDefinesTheResponseTypeForTheCounterpartyPayeeRpc**](QueryCounterpartyPayeeResponse_defines_the_response_type_for_the_CounterpartyPayee_rpc.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: */*

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)


## current_plan

> crate::models::CurrentPlanResponse current_plan()
CurrentPlan queries the current upgrade plan.

### Parameters

This endpoint does not need any parameter.

### Return type

[**crate::models::CurrentPlanResponse**](CurrentPlan_response.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: */*

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)


## delegation

> crate::models::DelegationResponse delegation(validator_addr, delegator_addr)
Delegation queries delegate info for given validator delegator pair.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**validator_addr** | **String** | validator_addr defines the validator address to query for. | [required] |
**delegator_addr** | **String** | delegator_addr defines the delegator address to query for. | [required] |

### Return type

[**crate::models::DelegationResponse**](Delegation_response.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: */*

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)


## delegation_rewards

> crate::models::DelegationRewardsResponse delegation_rewards(delegator_address, validator_address)
DelegationRewards queries the total rewards accrued by a delegation.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**delegator_address** | **String** | delegator_address defines the delegator address to query for. | [required] |
**validator_address** | **String** | validator_address defines the validator address to query for. | [required] |

### Return type

[**crate::models::DelegationRewardsResponse**](DelegationRewards_response.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: */*

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)


## delegation_total_rewards

> crate::models::DelegationTotalRewardsResponse delegation_total_rewards(delegator_address)
DelegationTotalRewards queries the total rewards accrued by a each validator.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**delegator_address** | **String** | delegator_address defines the delegator address to query for. | [required] |

### Return type

[**crate::models::DelegationTotalRewardsResponse**](DelegationTotalRewards_response.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: */*

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)


## delegator_delegations

> crate::models::DelegatorDelegationsResponse delegator_delegations(delegator_addr, pagination_period_key, pagination_period_offset, pagination_period_limit, pagination_period_count_total, pagination_period_reverse)
DelegatorDelegations queries all delegations of a given delegator address.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**delegator_addr** | **String** | delegator_addr defines the delegator address to query for. | [required] |
**pagination_period_key** | Option<**String**> | key is a value returned in PageResponse.next_key to begin querying the next page most efficiently. Only one of offset or key should be set. |  |
**pagination_period_offset** | Option<**String**> | offset is a numeric offset that can be used when key is unavailable. It is less efficient than using key. Only one of offset or key should be set. |  |
**pagination_period_limit** | Option<**String**> | limit is the total number of results to be returned in the result page. If left empty it will default to a value to be set by each app. |  |
**pagination_period_count_total** | Option<**bool**> | count_total is set to true  to indicate that the result set should include a count of the total number of items available for pagination in UIs. count_total is only respected when offset is used. It is ignored when key is set. |  |
**pagination_period_reverse** | Option<**bool**> | reverse is set to true if results are to be returned in the descending order.  Since: cosmos-sdk 0.43 |  |

### Return type

[**crate::models::DelegatorDelegationsResponse**](DelegatorDelegations_response.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: */*

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)


## delegator_unbonding_delegations

> crate::models::DelegatorUnbondingDelegationsResponse delegator_unbonding_delegations(delegator_addr, pagination_period_key, pagination_period_offset, pagination_period_limit, pagination_period_count_total, pagination_period_reverse)
DelegatorUnbondingDelegations queries all unbonding delegations of a given delegator address.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**delegator_addr** | **String** | delegator_addr defines the delegator address to query for. | [required] |
**pagination_period_key** | Option<**String**> | key is a value returned in PageResponse.next_key to begin querying the next page most efficiently. Only one of offset or key should be set. |  |
**pagination_period_offset** | Option<**String**> | offset is a numeric offset that can be used when key is unavailable. It is less efficient than using key. Only one of offset or key should be set. |  |
**pagination_period_limit** | Option<**String**> | limit is the total number of results to be returned in the result page. If left empty it will default to a value to be set by each app. |  |
**pagination_period_count_total** | Option<**bool**> | count_total is set to true  to indicate that the result set should include a count of the total number of items available for pagination in UIs. count_total is only respected when offset is used. It is ignored when key is set. |  |
**pagination_period_reverse** | Option<**bool**> | reverse is set to true if results are to be returned in the descending order.  Since: cosmos-sdk 0.43 |  |

### Return type

[**crate::models::DelegatorUnbondingDelegationsResponse**](DelegatorUnbondingDelegations_response.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: */*

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)


## delegator_validator

> crate::models::DelegatorValidatorResponse delegator_validator(delegator_addr, validator_addr)
DelegatorValidator queries validator info for given delegator validator pair.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**delegator_addr** | **String** | delegator_addr defines the delegator address to query for. | [required] |
**validator_addr** | **String** | validator_addr defines the validator address to query for. | [required] |

### Return type

[**crate::models::DelegatorValidatorResponse**](DelegatorValidator_response.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: */*

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)


## delegator_validators

> crate::models::DelegatorValidatorsResponse delegator_validators(delegator_address)
DelegatorValidators queries the validators of a delegator.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**delegator_address** | **String** | delegator_address defines the delegator address to query for. | [required] |

### Return type

[**crate::models::DelegatorValidatorsResponse**](DelegatorValidators_response.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: */*

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)


## delegator_validators_info

> crate::models::DelegatorValidatorsInfoResponse delegator_validators_info(delegator_addr, pagination_period_key, pagination_period_offset, pagination_period_limit, pagination_period_count_total, pagination_period_reverse)
DelegatorValidatorsInfo queries all validators info for given delegator address.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**delegator_addr** | **String** | delegator_addr defines the delegator address to query for. | [required] |
**pagination_period_key** | Option<**String**> | key is a value returned in PageResponse.next_key to begin querying the next page most efficiently. Only one of offset or key should be set. |  |
**pagination_period_offset** | Option<**String**> | offset is a numeric offset that can be used when key is unavailable. It is less efficient than using key. Only one of offset or key should be set. |  |
**pagination_period_limit** | Option<**String**> | limit is the total number of results to be returned in the result page. If left empty it will default to a value to be set by each app. |  |
**pagination_period_count_total** | Option<**bool**> | count_total is set to true  to indicate that the result set should include a count of the total number of items available for pagination in UIs. count_total is only respected when offset is used. It is ignored when key is set. |  |
**pagination_period_reverse** | Option<**bool**> | reverse is set to true if results are to be returned in the descending order.  Since: cosmos-sdk 0.43 |  |

### Return type

[**crate::models::DelegatorValidatorsInfoResponse**](DelegatorValidatorsInfo_response.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: */*

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)


## delegator_withdraw_address

> crate::models::DelegatorWithdrawAddressResponse delegator_withdraw_address(delegator_address)
DelegatorWithdrawAddress queries withdraw address of a delegator.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**delegator_address** | **String** | delegator_address defines the delegator address to query for. | [required] |

### Return type

[**crate::models::DelegatorWithdrawAddressResponse**](DelegatorWithdrawAddress_response.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: */*

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)


## denom_hash

> crate::models::DenomHashResponse denom_hash(trace)
DenomHash queries a denomination hash information.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**trace** | **String** | The denomination trace ([port_id]/[channel_id])+/[denom] | [required] |

### Return type

[**crate::models::DenomHashResponse**](DenomHash_response.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: */*

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)


## denom_metadata

> crate::models::DenomMetadataResponse denom_metadata(denom)
DenomsMetadata queries the client metadata of a given coin denomination.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**denom** | **String** | denom is the coin denom to query the metadata for. | [required] |

### Return type

[**crate::models::DenomMetadataResponse**](DenomMetadata_response.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: */*

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)


## denom_trace

> crate::models::DenomTraceResponse denom_trace(hash)
DenomTrace queries a denomination trace information.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**hash** | **String** | hash (in hex format) or denom (full denom with ibc prefix) of the denomination trace information. | [required] |

### Return type

[**crate::models::DenomTraceResponse**](DenomTrace_response.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: */*

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)


## denom_traces

> crate::models::DenomTracesResponse denom_traces(pagination_period_key, pagination_period_offset, pagination_period_limit, pagination_period_count_total, pagination_period_reverse)
DenomTraces queries all denomination traces.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**pagination_period_key** | Option<**String**> | key is a value returned in PageResponse.next_key to begin querying the next page most efficiently. Only one of offset or key should be set. |  |
**pagination_period_offset** | Option<**String**> | offset is a numeric offset that can be used when key is unavailable. It is less efficient than using key. Only one of offset or key should be set. |  |
**pagination_period_limit** | Option<**String**> | limit is the total number of results to be returned in the result page. If left empty it will default to a value to be set by each app. |  |
**pagination_period_count_total** | Option<**bool**> | count_total is set to true  to indicate that the result set should include a count of the total number of items available for pagination in UIs. count_total is only respected when offset is used. It is ignored when key is set. |  |
**pagination_period_reverse** | Option<**bool**> | reverse is set to true if results are to be returned in the descending order.  Since: cosmos-sdk 0.43 |  |

### Return type

[**crate::models::DenomTracesResponse**](DenomTraces_response.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: */*

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)


## denoms_metadata

> crate::models::DenomsMetadataResponse denoms_metadata(pagination_period_key, pagination_period_offset, pagination_period_limit, pagination_period_count_total, pagination_period_reverse)
DenomsMetadata queries the client metadata for all registered coin denominations.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**pagination_period_key** | Option<**String**> | key is a value returned in PageResponse.next_key to begin querying the next page most efficiently. Only one of offset or key should be set. |  |
**pagination_period_offset** | Option<**String**> | offset is a numeric offset that can be used when key is unavailable. It is less efficient than using key. Only one of offset or key should be set. |  |
**pagination_period_limit** | Option<**String**> | limit is the total number of results to be returned in the result page. If left empty it will default to a value to be set by each app. |  |
**pagination_period_count_total** | Option<**bool**> | count_total is set to true  to indicate that the result set should include a count of the total number of items available for pagination in UIs. count_total is only respected when offset is used. It is ignored when key is set. |  |
**pagination_period_reverse** | Option<**bool**> | reverse is set to true if results are to be returned in the descending order.  Since: cosmos-sdk 0.43 |  |

### Return type

[**crate::models::DenomsMetadataResponse**](DenomsMetadata_response.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: */*

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)


## deposit

> crate::models::DepositResponse deposit(proposal_id, depositor)
Deposit queries single deposit information based proposalID, depositAddr.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**proposal_id** | **String** | proposal_id defines the unique id of the proposal. | [required] |
**depositor** | **String** | depositor defines the deposit addresses from the proposals. | [required] |

### Return type

[**crate::models::DepositResponse**](Deposit_response.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: */*

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)


## deposits

> crate::models::DepositsResponse deposits(proposal_id, pagination_period_key, pagination_period_offset, pagination_period_limit, pagination_period_count_total, pagination_period_reverse)
Deposits queries all deposits of a single proposal.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**proposal_id** | **String** | proposal_id defines the unique id of the proposal. | [required] |
**pagination_period_key** | Option<**String**> | key is a value returned in PageResponse.next_key to begin querying the next page most efficiently. Only one of offset or key should be set. |  |
**pagination_period_offset** | Option<**String**> | offset is a numeric offset that can be used when key is unavailable. It is less efficient than using key. Only one of offset or key should be set. |  |
**pagination_period_limit** | Option<**String**> | limit is the total number of results to be returned in the result page. If left empty it will default to a value to be set by each app. |  |
**pagination_period_count_total** | Option<**bool**> | count_total is set to true  to indicate that the result set should include a count of the total number of items available for pagination in UIs. count_total is only respected when offset is used. It is ignored when key is set. |  |
**pagination_period_reverse** | Option<**bool**> | reverse is set to true if results are to be returned in the descending order.  Since: cosmos-sdk 0.43 |  |

### Return type

[**crate::models::DepositsResponse**](Deposits_response.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: */*

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)


## distribution_params

> crate::models::DistributionParamsResponse distribution_params()
Params queries params of the distribution module.

### Parameters

This endpoint does not need any parameter.

### Return type

[**crate::models::DistributionParamsResponse**](DistributionParams_response.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: */*

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)


## emergency_button_params

> crate::models::EmergencyButtonParamsResponse emergency_button_params()
Params defines a gRPC query method that returns the emergencybutton module's parameters.

### Parameters

This endpoint does not need any parameter.

### Return type

[**crate::models::EmergencyButtonParamsResponse**](EmergencyButtonParams_response.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: */*

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)


## encrypted_seed

> crate::models::EncryptedSeedResponse encrypted_seed(pub_key)
Returns the encrypted seed for a registered node by public key

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**pub_key** | **String** |  | [required] |

### Return type

[**crate::models::EncryptedSeedResponse**](EncryptedSeed_response.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: */*

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)


## escrow_address

> crate::models::EscrowAddressResponse escrow_address(channel_id, port_id)
EscrowAddress returns the escrow address for a particular port and channel id.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**channel_id** | **String** | unique channel identifier | [required] |
**port_id** | **String** | unique port identifier | [required] |

### Return type

[**crate::models::EscrowAddressResponse**](EscrowAddress_response.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: */*

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)


## evidence

> crate::models::EvidenceResponse evidence(evidence_hash)
Evidence queries evidence based on evidence hash.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**evidence_hash** | **String** | evidence_hash defines the hash of the requested evidence. | [required] |

### Return type

[**crate::models::EvidenceResponse**](Evidence_response.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: */*

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)


## fee_enabled_channel

> crate::models::QueryFeeEnabledChannelResponseDefinesTheResponseTypeForTheFeeEnabledChannelRpc fee_enabled_channel(channel_id, port_id)
FeeEnabledChannel returns true if the provided port and channel identifiers belong to a fee enabled channel

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**channel_id** | **String** | unique channel identifier | [required] |
**port_id** | **String** | unique port identifier | [required] |

### Return type

[**crate::models::QueryFeeEnabledChannelResponseDefinesTheResponseTypeForTheFeeEnabledChannelRpc**](QueryFeeEnabledChannelResponse_defines_the_response_type_for_the_FeeEnabledChannel_rpc.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: */*

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)


## fee_enabled_channels

> crate::models::QueryFeeEnabledChannelsResponseDefinesTheResponseTypeForTheFeeEnabledChannelsRpc fee_enabled_channels(pagination_period_key, pagination_period_offset, pagination_period_limit, pagination_period_count_total, pagination_period_reverse, query_height)
FeeEnabledChannels returns a list of all fee enabled channels

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**pagination_period_key** | Option<**String**> | key is a value returned in PageResponse.next_key to begin querying the next page most efficiently. Only one of offset or key should be set. |  |
**pagination_period_offset** | Option<**String**> | offset is a numeric offset that can be used when key is unavailable. It is less efficient than using key. Only one of offset or key should be set. |  |
**pagination_period_limit** | Option<**String**> | limit is the total number of results to be returned in the result page. If left empty it will default to a value to be set by each app. |  |
**pagination_period_count_total** | Option<**bool**> | count_total is set to true  to indicate that the result set should include a count of the total number of items available for pagination in UIs. count_total is only respected when offset is used. It is ignored when key is set. |  |
**pagination_period_reverse** | Option<**bool**> | reverse is set to true if results are to be returned in the descending order.  Since: cosmos-sdk 0.43 |  |
**query_height** | Option<**String**> | block height at which to query. |  |

### Return type

[**crate::models::QueryFeeEnabledChannelsResponseDefinesTheResponseTypeForTheFeeEnabledChannelsRpc**](QueryFeeEnabledChannelsResponse_defines_the_response_type_for_the_FeeEnabledChannels_rpc.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: */*

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)


## foundation_tax

> crate::models::FoundationTaxResponse foundation_tax()
DelegatorWithdrawAddress queries withdraw address of a delegator.

### Parameters

This endpoint does not need any parameter.

### Return type

[**crate::models::FoundationTaxResponse**](FoundationTax_response.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: */*

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)


## get_block_by_height

> crate::models::GetBlockByHeightResponse get_block_by_height(height)
GetBlockByHeight queries block for given height.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**height** | **String** |  | [required] |

### Return type

[**crate::models::GetBlockByHeightResponse**](GetBlockByHeight_response.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: */*

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)


## get_block_with_txs

> crate::models::GetBlockWithTxsResponse get_block_with_txs(height, pagination_period_key, pagination_period_offset, pagination_period_limit, pagination_period_count_total, pagination_period_reverse)
GetBlockWithTxs fetches a block with decoded txs.

Since: cosmos-sdk 0.45.2

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**height** | **String** | height is the height of the block to query. | [required] |
**pagination_period_key** | Option<**String**> | key is a value returned in PageResponse.next_key to begin querying the next page most efficiently. Only one of offset or key should be set. |  |
**pagination_period_offset** | Option<**String**> | offset is a numeric offset that can be used when key is unavailable. It is less efficient than using key. Only one of offset or key should be set. |  |
**pagination_period_limit** | Option<**String**> | limit is the total number of results to be returned in the result page. If left empty it will default to a value to be set by each app. |  |
**pagination_period_count_total** | Option<**bool**> | count_total is set to true  to indicate that the result set should include a count of the total number of items available for pagination in UIs. count_total is only respected when offset is used. It is ignored when key is set. |  |
**pagination_period_reverse** | Option<**bool**> | reverse is set to true if results are to be returned in the descending order.  Since: cosmos-sdk 0.43 |  |

### Return type

[**crate::models::GetBlockWithTxsResponse**](GetBlockWithTxs_response.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: */*

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)


## get_latest_block

> crate::models::GetLatestBlockResponse get_latest_block()
GetLatestBlock returns the latest block.

### Parameters

This endpoint does not need any parameter.

### Return type

[**crate::models::GetLatestBlockResponse**](GetLatestBlock_response.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: */*

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)


## get_latest_validator_set

> crate::models::GetLatestValidatorSetResponse get_latest_validator_set(pagination_period_key, pagination_period_offset, pagination_period_limit, pagination_period_count_total, pagination_period_reverse)
GetLatestValidatorSet queries latest validator-set.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**pagination_period_key** | Option<**String**> | key is a value returned in PageResponse.next_key to begin querying the next page most efficiently. Only one of offset or key should be set. |  |
**pagination_period_offset** | Option<**String**> | offset is a numeric offset that can be used when key is unavailable. It is less efficient than using key. Only one of offset or key should be set. |  |
**pagination_period_limit** | Option<**String**> | limit is the total number of results to be returned in the result page. If left empty it will default to a value to be set by each app. |  |
**pagination_period_count_total** | Option<**bool**> | count_total is set to true  to indicate that the result set should include a count of the total number of items available for pagination in UIs. count_total is only respected when offset is used. It is ignored when key is set. |  |
**pagination_period_reverse** | Option<**bool**> | reverse is set to true if results are to be returned in the descending order.  Since: cosmos-sdk 0.43 |  |

### Return type

[**crate::models::GetLatestValidatorSetResponse**](GetLatestValidatorSet_response.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: */*

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)


## get_node_info

> crate::models::GetNodeInfoResponse get_node_info()
GetNodeInfo queries the current node info.

### Parameters

This endpoint does not need any parameter.

### Return type

[**crate::models::GetNodeInfoResponse**](GetNodeInfo_response.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: */*

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)


## get_syncing

> crate::models::GetSyncingResponse get_syncing()
GetSyncing queries node syncing.

### Parameters

This endpoint does not need any parameter.

### Return type

[**crate::models::GetSyncingResponse**](GetSyncing_response.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: */*

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)


## get_tx

> crate::models::GetTxResponse get_tx(hash)
GetTx fetches a tx by hash.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**hash** | **String** | hash is the tx hash to query, encoded as a hex string. | [required] |

### Return type

[**crate::models::GetTxResponse**](GetTx_response.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: */*

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)


## get_txs_event

> crate::models::GetTxsEventResponse get_txs_event(events, pagination_period_key, pagination_period_offset, pagination_period_limit, pagination_period_count_total, pagination_period_reverse, order_by)
GetTxsEvent fetches txs by event.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**events** | Option<[**Vec<String>**](String.md)> | events is the list of transaction event type. |  |
**pagination_period_key** | Option<**String**> | key is a value returned in PageResponse.next_key to begin querying the next page most efficiently. Only one of offset or key should be set. |  |
**pagination_period_offset** | Option<**String**> | offset is a numeric offset that can be used when key is unavailable. It is less efficient than using key. Only one of offset or key should be set. |  |
**pagination_period_limit** | Option<**String**> | limit is the total number of results to be returned in the result page. If left empty it will default to a value to be set by each app. |  |
**pagination_period_count_total** | Option<**bool**> | count_total is set to true  to indicate that the result set should include a count of the total number of items available for pagination in UIs. count_total is only respected when offset is used. It is ignored when key is set. |  |
**pagination_period_reverse** | Option<**bool**> | reverse is set to true if results are to be returned in the descending order.  Since: cosmos-sdk 0.43 |  |
**order_by** | Option<**String**> |  - ORDER_BY_UNSPECIFIED: ORDER_BY_UNSPECIFIED specifies an unknown sorting order. OrderBy defaults to ASC in this case.  - ORDER_BY_ASC: ORDER_BY_ASC defines ascending order  - ORDER_BY_DESC: ORDER_BY_DESC defines descending order |  |[default to ORDER_BY_UNSPECIFIED]

### Return type

[**crate::models::GetTxsEventResponse**](GetTxsEvent_response.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: */*

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)


## get_validator_set_by_height

> crate::models::GetValidatorSetByHeightResponse get_validator_set_by_height(height, pagination_period_key, pagination_period_offset, pagination_period_limit, pagination_period_count_total, pagination_period_reverse)
GetValidatorSetByHeight queries validator-set at a given height.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**height** | **String** |  | [required] |
**pagination_period_key** | Option<**String**> | key is a value returned in PageResponse.next_key to begin querying the next page most efficiently. Only one of offset or key should be set. |  |
**pagination_period_offset** | Option<**String**> | offset is a numeric offset that can be used when key is unavailable. It is less efficient than using key. Only one of offset or key should be set. |  |
**pagination_period_limit** | Option<**String**> | limit is the total number of results to be returned in the result page. If left empty it will default to a value to be set by each app. |  |
**pagination_period_count_total** | Option<**bool**> | count_total is set to true  to indicate that the result set should include a count of the total number of items available for pagination in UIs. count_total is only respected when offset is used. It is ignored when key is set. |  |
**pagination_period_reverse** | Option<**bool**> | reverse is set to true if results are to be returned in the descending order.  Since: cosmos-sdk 0.43 |  |

### Return type

[**crate::models::GetValidatorSetByHeightResponse**](GetValidatorSetByHeight_response.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: */*

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)


## gov_params

> crate::models::GovParamsResponse gov_params(params_type)
Params queries all parameters of the gov module.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**params_type** | **String** | params_type defines which parameters to query for, can be one of \"voting\", \"tallying\" or \"deposit\". | [required] |

### Return type

[**crate::models::GovParamsResponse**](GovParams_response.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: */*

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)


## grantee_grants

> crate::models::GranteeGrantsResponse grantee_grants(grantee, pagination_period_key, pagination_period_offset, pagination_period_limit, pagination_period_count_total, pagination_period_reverse)
GranteeGrants returns a list of `GrantAuthorization` by grantee.

Since: cosmos-sdk 0.45.2

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**grantee** | **String** |  | [required] |
**pagination_period_key** | Option<**String**> | key is a value returned in PageResponse.next_key to begin querying the next page most efficiently. Only one of offset or key should be set. |  |
**pagination_period_offset** | Option<**String**> | offset is a numeric offset that can be used when key is unavailable. It is less efficient than using key. Only one of offset or key should be set. |  |
**pagination_period_limit** | Option<**String**> | limit is the total number of results to be returned in the result page. If left empty it will default to a value to be set by each app. |  |
**pagination_period_count_total** | Option<**bool**> | count_total is set to true  to indicate that the result set should include a count of the total number of items available for pagination in UIs. count_total is only respected when offset is used. It is ignored when key is set. |  |
**pagination_period_reverse** | Option<**bool**> | reverse is set to true if results are to be returned in the descending order.  Since: cosmos-sdk 0.43 |  |

### Return type

[**crate::models::GranteeGrantsResponse**](GranteeGrants_response.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: */*

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)


## granter_grants

> crate::models::GranterGrantsResponse granter_grants(granter, pagination_period_key, pagination_period_offset, pagination_period_limit, pagination_period_count_total, pagination_period_reverse)
GranterGrants returns list of `GrantAuthorization`, granted by granter.

Since: cosmos-sdk 0.45.2

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**granter** | **String** |  | [required] |
**pagination_period_key** | Option<**String**> | key is a value returned in PageResponse.next_key to begin querying the next page most efficiently. Only one of offset or key should be set. |  |
**pagination_period_offset** | Option<**String**> | offset is a numeric offset that can be used when key is unavailable. It is less efficient than using key. Only one of offset or key should be set. |  |
**pagination_period_limit** | Option<**String**> | limit is the total number of results to be returned in the result page. If left empty it will default to a value to be set by each app. |  |
**pagination_period_count_total** | Option<**bool**> | count_total is set to true  to indicate that the result set should include a count of the total number of items available for pagination in UIs. count_total is only respected when offset is used. It is ignored when key is set. |  |
**pagination_period_reverse** | Option<**bool**> | reverse is set to true if results are to be returned in the descending order.  Since: cosmos-sdk 0.43 |  |

### Return type

[**crate::models::GranterGrantsResponse**](GranterGrants_response.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: */*

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)


## grants

> crate::models::GrantsResponse grants(granter, grantee, msg_type_url, pagination_period_key, pagination_period_offset, pagination_period_limit, pagination_period_count_total, pagination_period_reverse)
Returns list of `Authorization`, granted to the grantee by the granter.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**granter** | Option<**String**> |  |  |
**grantee** | Option<**String**> |  |  |
**msg_type_url** | Option<**String**> | Optional, msg_type_url, when set, will query only grants matching given msg type. |  |
**pagination_period_key** | Option<**String**> | key is a value returned in PageResponse.next_key to begin querying the next page most efficiently. Only one of offset or key should be set. |  |
**pagination_period_offset** | Option<**String**> | offset is a numeric offset that can be used when key is unavailable. It is less efficient than using key. Only one of offset or key should be set. |  |
**pagination_period_limit** | Option<**String**> | limit is the total number of results to be returned in the result page. If left empty it will default to a value to be set by each app. |  |
**pagination_period_count_total** | Option<**bool**> | count_total is set to true  to indicate that the result set should include a count of the total number of items available for pagination in UIs. count_total is only respected when offset is used. It is ignored when key is set. |  |
**pagination_period_reverse** | Option<**bool**> | reverse is set to true if results are to be returned in the descending order.  Since: cosmos-sdk 0.43 |  |

### Return type

[**crate::models::GrantsResponse**](Grants_response.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: */*

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)


## historical_info

> crate::models::HistoricalInfoResponse historical_info(height)
HistoricalInfo queries the historical info for given height.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**height** | **String** | height defines at which height to query the historical info. | [required] |

### Return type

[**crate::models::HistoricalInfoResponse**](HistoricalInfo_response.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: */*

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)


## host_params

> crate::models::HostParamsResponse host_params()
Params queries all parameters of the ICA host submodule.

### Parameters

This endpoint does not need any parameter.

### Return type

[**crate::models::HostParamsResponse**](HostParams_response.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: */*

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)


## incentivized_packet

> crate::models::QueryIncentivizedPacketsResponseDefinesTheResponseTypeForTheIncentivizedPacketRpc incentivized_packet(packet_id_period_channel_id, packet_id_period_port_id, packet_id_period_sequence, query_height)
IncentivizedPacket returns all packet fees for a packet given its identifier

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**packet_id_period_channel_id** | **String** | channel unique identifier | [required] |
**packet_id_period_port_id** | **String** | channel port identifier | [required] |
**packet_id_period_sequence** | **String** | packet sequence | [required] |
**query_height** | Option<**String**> | block height at which to query. |  |

### Return type

[**crate::models::QueryIncentivizedPacketsResponseDefinesTheResponseTypeForTheIncentivizedPacketRpc**](QueryIncentivizedPacketsResponse_defines_the_response_type_for_the_IncentivizedPacket_rpc.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: */*

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)


## incentivized_packets

> crate::models::QueryIncentivizedPacketsResponseDefinesTheResponseTypeForTheIncentivizedPacketsRpc incentivized_packets(pagination_period_key, pagination_period_offset, pagination_period_limit, pagination_period_count_total, pagination_period_reverse, query_height)
IncentivizedPackets returns all incentivized packets and their associated fees

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**pagination_period_key** | Option<**String**> | key is a value returned in PageResponse.next_key to begin querying the next page most efficiently. Only one of offset or key should be set. |  |
**pagination_period_offset** | Option<**String**> | offset is a numeric offset that can be used when key is unavailable. It is less efficient than using key. Only one of offset or key should be set. |  |
**pagination_period_limit** | Option<**String**> | limit is the total number of results to be returned in the result page. If left empty it will default to a value to be set by each app. |  |
**pagination_period_count_total** | Option<**bool**> | count_total is set to true  to indicate that the result set should include a count of the total number of items available for pagination in UIs. count_total is only respected when offset is used. It is ignored when key is set. |  |
**pagination_period_reverse** | Option<**bool**> | reverse is set to true if results are to be returned in the descending order.  Since: cosmos-sdk 0.43 |  |
**query_height** | Option<**String**> | block height at which to query. |  |

### Return type

[**crate::models::QueryIncentivizedPacketsResponseDefinesTheResponseTypeForTheIncentivizedPacketsRpc**](QueryIncentivizedPacketsResponse_defines_the_response_type_for_the_IncentivizedPackets_rpc.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: */*

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)


## incentivized_packets_for_channel

> crate::models::QueryIncentivizedPacketsResponseDefinesTheResponseTypeForTheIncentivizedPacketsRpc incentivized_packets_for_channel(channel_id, port_id, pagination_period_key, pagination_period_offset, pagination_period_limit, pagination_period_count_total, pagination_period_reverse, query_height)
Gets all incentivized packets for a specific channel

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**channel_id** | **String** |  | [required] |
**port_id** | **String** |  | [required] |
**pagination_period_key** | Option<**String**> | key is a value returned in PageResponse.next_key to begin querying the next page most efficiently. Only one of offset or key should be set. |  |
**pagination_period_offset** | Option<**String**> | offset is a numeric offset that can be used when key is unavailable. It is less efficient than using key. Only one of offset or key should be set. |  |
**pagination_period_limit** | Option<**String**> | limit is the total number of results to be returned in the result page. If left empty it will default to a value to be set by each app. |  |
**pagination_period_count_total** | Option<**bool**> | count_total is set to true  to indicate that the result set should include a count of the total number of items available for pagination in UIs. count_total is only respected when offset is used. It is ignored when key is set. |  |
**pagination_period_reverse** | Option<**bool**> | reverse is set to true if results are to be returned in the descending order.  Since: cosmos-sdk 0.43 |  |
**query_height** | Option<**String**> | Height to query at. |  |

### Return type

[**crate::models::QueryIncentivizedPacketsResponseDefinesTheResponseTypeForTheIncentivizedPacketsRpc**](QueryIncentivizedPacketsResponse_defines_the_response_type_for_the_incentivized_packets_RPC.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: */*

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)


## inflation

> crate::models::InflationResponse inflation()
Inflation returns the current minting inflation value.

### Parameters

This endpoint does not need any parameter.

### Return type

[**crate::models::InflationResponse**](Inflation_response.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: */*

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)


## interchain_account

> crate::models::InterchainAccountResponse interchain_account(owner, connection_id)
InterchainAccount returns the interchain account address for a given owner address on a given connection

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**owner** | **String** |  | [required] |
**connection_id** | **String** |  | [required] |

### Return type

[**crate::models::InterchainAccountResponse**](InterchainAccount_response.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: */*

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)


## interchain_account_from_address

> crate::models::QueryInterchainAccountFromAddressResponseTheResponseTypeForTheQueryInterchainAccountAddressRpc interchain_account_from_address(owner, connection_id)
QueryInterchainAccountFromAddress returns the interchain account for given owner address on a given connection pair

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**owner** | **String** |  | [required] |
**connection_id** | **String** |  | [required] |

### Return type

[**crate::models::QueryInterchainAccountFromAddressResponseTheResponseTypeForTheQueryInterchainAccountAddressRpc**](QueryInterchainAccountFromAddressResponse_the_response_type_for_the_Query_InterchainAccountAddress_RPC.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: */*

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)


## label_by_address

> crate::models::LabelByAddressResponse label_by_address(contract_address)
Query contract label by address

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**contract_address** | **String** | address is the bech32 human readable address of the contract | [required] |

### Return type

[**crate::models::LabelByAddressResponse**](LabelByAddress_response.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: */*

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)


## mint_params

> crate::models::MintParamsResponse mint_params()
Params returns the total set of minting parameters.

### Parameters

This endpoint does not need any parameter.

### Return type

[**crate::models::MintParamsResponse**](MintParams_response.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: */*

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)


## module_account_by_name

> crate::models::ModuleAccountByNameResponse module_account_by_name(name)
ModuleAccountByName returns the module account info by module name

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**name** | **String** |  | [required] |

### Return type

[**crate::models::ModuleAccountByNameResponse**](ModuleAccountByName_response.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: */*

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)


## module_versions

> crate::models::ModuleVersionsResponse module_versions(module_name)
ModuleVersions queries the list of module versions from state.

Since: cosmos-sdk 0.43

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**module_name** | Option<**String**> | module_name is a field to query a specific module consensus version from state. Leaving this empty will fetch the full list of module versions from state. |  |

### Return type

[**crate::models::ModuleVersionsResponse**](ModuleVersions_response.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: */*

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)


## next_sequence_receive

> crate::models::QuerySequenceResponseIsTheRequestTypeForTheQueryQueryNextSequenceReceiveResponseRpcMethod next_sequence_receive(channel_id, port_id)
NextSequenceReceive returns the next receive sequence for a given channel.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**channel_id** | **String** | channel unique identifier | [required] |
**port_id** | **String** | port unique identifier | [required] |

### Return type

[**crate::models::QuerySequenceResponseIsTheRequestTypeForTheQueryQueryNextSequenceReceiveResponseRpcMethod**](QuerySequenceResponse_is_the_request_type_for_the_Query_QueryNextSequenceReceiveResponse_RPC_method.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: */*

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)


## packet_acknowledgement

> crate::models::QueryPacketAcknowledgementResponseDefinesTheClientQueryResponseForAPacketWhichAlsoIncludesAProofAndTheHeightFromWhichTheProofWasRetrieved packet_acknowledgement(channel_id, port_id, sequence)
PacketAcknowledgement queries a stored packet acknowledgement hash.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**channel_id** | **String** | channel unique identifier | [required] |
**port_id** | **String** | port unique identifier | [required] |
**sequence** | **String** | packet sequence | [required] |

### Return type

[**crate::models::QueryPacketAcknowledgementResponseDefinesTheClientQueryResponseForAPacketWhichAlsoIncludesAProofAndTheHeightFromWhichTheProofWasRetrieved**](QueryPacketAcknowledgementResponse_defines_the_client_query_response_for_a_packet_which_also_includes_a_proof_and_the_height_from_which_the_proof_was_retrieved.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: */*

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)


## packet_acknowledgements

> crate::models::QueryPacketAcknowledgemetsResponseIsTheRequestTypeForTheQueryQueryPacketAcknowledgementsRpcMethod packet_acknowledgements(channel_id, port_id, pagination_period_key, pagination_period_offset, pagination_period_limit, pagination_period_count_total, pagination_period_reverse, packet_commitment_sequences)
PacketAcknowledgements returns all the packet acknowledgements associated with a channel.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**channel_id** | **String** | channel unique identifier | [required] |
**port_id** | **String** | port unique identifier | [required] |
**pagination_period_key** | Option<**String**> | key is a value returned in PageResponse.next_key to begin querying the next page most efficiently. Only one of offset or key should be set. |  |
**pagination_period_offset** | Option<**String**> | offset is a numeric offset that can be used when key is unavailable. It is less efficient than using key. Only one of offset or key should be set. |  |
**pagination_period_limit** | Option<**String**> | limit is the total number of results to be returned in the result page. If left empty it will default to a value to be set by each app. |  |
**pagination_period_count_total** | Option<**bool**> | count_total is set to true  to indicate that the result set should include a count of the total number of items available for pagination in UIs. count_total is only respected when offset is used. It is ignored when key is set. |  |
**pagination_period_reverse** | Option<**bool**> | reverse is set to true if results are to be returned in the descending order.  Since: cosmos-sdk 0.43 |  |
**packet_commitment_sequences** | Option<[**Vec<String>**](String.md)> | list of packet sequences. |  |

### Return type

[**crate::models::QueryPacketAcknowledgemetsResponseIsTheRequestTypeForTheQueryQueryPacketAcknowledgementsRpcMethod**](QueryPacketAcknowledgemetsResponse_is_the_request_type_for_the_Query_QueryPacketAcknowledgements_RPC_method.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: */*

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)


## packet_commitment

> crate::models::QueryPacketCommitmentResponseDefinesTheClientQueryResponseForAPacketWhichAlsoIncludesAProofAndTheHeightFromWhichTheProofWasRetrieved packet_commitment(channel_id, port_id, sequence)
PacketCommitment queries a stored packet commitment hash.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**channel_id** | **String** | channel unique identifier | [required] |
**port_id** | **String** | port unique identifier | [required] |
**sequence** | **String** | packet sequence | [required] |

### Return type

[**crate::models::QueryPacketCommitmentResponseDefinesTheClientQueryResponseForAPacketWhichAlsoIncludesAProofAndTheHeightFromWhichTheProofWasRetrieved**](QueryPacketCommitmentResponse_defines_the_client_query_response_for_a_packet_which_also_includes_a_proof_and_the_height_from_which_the_proof_was_retrieved.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: */*

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)


## packet_commitments

> crate::models::QueryPacketCommitmentsResponseIsTheRequestTypeForTheQueryQueryPacketCommitmentsRpcMethod packet_commitments(channel_id, port_id, pagination_period_key, pagination_period_offset, pagination_period_limit, pagination_period_count_total, pagination_period_reverse)
PacketCommitments returns all the packet commitments hashes associated with a channel.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**channel_id** | **String** | channel unique identifier | [required] |
**port_id** | **String** | port unique identifier | [required] |
**pagination_period_key** | Option<**String**> | key is a value returned in PageResponse.next_key to begin querying the next page most efficiently. Only one of offset or key should be set. |  |
**pagination_period_offset** | Option<**String**> | offset is a numeric offset that can be used when key is unavailable. It is less efficient than using key. Only one of offset or key should be set. |  |
**pagination_period_limit** | Option<**String**> | limit is the total number of results to be returned in the result page. If left empty it will default to a value to be set by each app. |  |
**pagination_period_count_total** | Option<**bool**> | count_total is set to true  to indicate that the result set should include a count of the total number of items available for pagination in UIs. count_total is only respected when offset is used. It is ignored when key is set. |  |
**pagination_period_reverse** | Option<**bool**> | reverse is set to true if results are to be returned in the descending order.  Since: cosmos-sdk 0.43 |  |

### Return type

[**crate::models::QueryPacketCommitmentsResponseIsTheRequestTypeForTheQueryQueryPacketCommitmentsRpcMethod**](QueryPacketCommitmentsResponse_is_the_request_type_for_the_Query_QueryPacketCommitments_RPC_method.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: */*

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)


## packet_receipt

> crate::models::QueryPacketReceiptResponseDefinesTheClientQueryResponseForAPacketReceiptWhichAlsoIncludesAProofAndTheHeightFromWhichTheProofWasRetrieved packet_receipt(channel_id, port_id, sequence)
PacketReceipt queries if a given packet sequence has been received on the queried chain

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**channel_id** | **String** | channel unique identifier | [required] |
**port_id** | **String** | port unique identifier | [required] |
**sequence** | **String** | packet sequence | [required] |

### Return type

[**crate::models::QueryPacketReceiptResponseDefinesTheClientQueryResponseForAPacketReceiptWhichAlsoIncludesAProofAndTheHeightFromWhichTheProofWasRetrieved**](QueryPacketReceiptResponse_defines_the_client_query_response_for_a_packet_receipt_which_also_includes_a_proof__and_the_height_from_which_the_proof_was_retrieved.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: */*

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)


## params

> crate::models::ParamsResponse params(subspace, key)
Params queries a specific parameter of a module, given its subspace and key.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**subspace** | Option<**String**> | subspace defines the module to query the parameter for. |  |
**key** | Option<**String**> | key defines the key of the parameter in the subspace. |  |

### Return type

[**crate::models::ParamsResponse**](Params_response.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: */*

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)


## payee

> crate::models::QueryPayeeResponseDefinesTheResponseTypeForThePayeeRpc payee(channel_id, relayer)
Payee returns the registered payee address for a specific channel given the relayer address

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**channel_id** | **String** | unique channel identifier | [required] |
**relayer** | **String** | the relayer address to which the distribution address is registered | [required] |

### Return type

[**crate::models::QueryPayeeResponseDefinesTheResponseTypeForThePayeeRpc**](QueryPayeeResponse_defines_the_response_type_for_the_Payee_rpc.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: */*

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)


## pool

> crate::models::PoolResponse pool()
Pool queries the pool info.

### Parameters

This endpoint does not need any parameter.

### Return type

[**crate::models::PoolResponse**](Pool_response.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: */*

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)


## proposal

> crate::models::ProposalResponse proposal(proposal_id)
Proposal queries proposal details based on ProposalID.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**proposal_id** | **String** | proposal_id defines the unique id of the proposal. | [required] |

### Return type

[**crate::models::ProposalResponse**](Proposal_response.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: */*

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)


## proposals

> crate::models::ProposalsResponse proposals(proposal_status, voter, depositor, pagination_period_key, pagination_period_offset, pagination_period_limit, pagination_period_count_total, pagination_period_reverse)
Proposals queries all proposals based on given status.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**proposal_status** | Option<**String**> | proposal_status defines the status of the proposals.   - PROPOSAL_STATUS_UNSPECIFIED: PROPOSAL_STATUS_UNSPECIFIED defines the default propopsal status.  - PROPOSAL_STATUS_DEPOSIT_PERIOD: PROPOSAL_STATUS_DEPOSIT_PERIOD defines a proposal status during the deposit period.  - PROPOSAL_STATUS_VOTING_PERIOD: PROPOSAL_STATUS_VOTING_PERIOD defines a proposal status during the voting period.  - PROPOSAL_STATUS_PASSED: PROPOSAL_STATUS_PASSED defines a proposal status of a proposal that has passed.  - PROPOSAL_STATUS_REJECTED: PROPOSAL_STATUS_REJECTED defines a proposal status of a proposal that has been rejected.  - PROPOSAL_STATUS_FAILED: PROPOSAL_STATUS_FAILED defines a proposal status of a proposal that has failed. |  |[default to PROPOSAL_STATUS_UNSPECIFIED]
**voter** | Option<**String**> | voter defines the voter address for the proposals. |  |
**depositor** | Option<**String**> | depositor defines the deposit addresses from the proposals. |  |
**pagination_period_key** | Option<**String**> | key is a value returned in PageResponse.next_key to begin querying the next page most efficiently. Only one of offset or key should be set. |  |
**pagination_period_offset** | Option<**String**> | offset is a numeric offset that can be used when key is unavailable. It is less efficient than using key. Only one of offset or key should be set. |  |
**pagination_period_limit** | Option<**String**> | limit is the total number of results to be returned in the result page. If left empty it will default to a value to be set by each app. |  |
**pagination_period_count_total** | Option<**bool**> | count_total is set to true  to indicate that the result set should include a count of the total number of items available for pagination in UIs. count_total is only respected when offset is used. It is ignored when key is set. |  |
**pagination_period_reverse** | Option<**bool**> | reverse is set to true if results are to be returned in the descending order.  Since: cosmos-sdk 0.43 |  |

### Return type

[**crate::models::ProposalsResponse**](Proposals_response.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: */*

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)


## query_secret_contract

> crate::models::QuerySecretContractResponse query_secret_contract(contract_address, query)
Query secret contract

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**contract_address** | **String** | address is the bech32 human readable address of the contract | [required] |
**query** | Option<**String**> |  |  |

### Return type

[**crate::models::QuerySecretContractResponse**](QuerySecretContract_response.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: */*

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)


## redelegations

> crate::models::RedelegationsResponse redelegations(delegator_addr, src_validator_addr, dst_validator_addr, pagination_period_key, pagination_period_offset, pagination_period_limit, pagination_period_count_total, pagination_period_reverse)
Redelegations queries redelegations of given address.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**delegator_addr** | **String** | delegator_addr defines the delegator address to query for. | [required] |
**src_validator_addr** | Option<**String**> | src_validator_addr defines the validator address to redelegate from. |  |
**dst_validator_addr** | Option<**String**> | dst_validator_addr defines the validator address to redelegate to. |  |
**pagination_period_key** | Option<**String**> | key is a value returned in PageResponse.next_key to begin querying the next page most efficiently. Only one of offset or key should be set. |  |
**pagination_period_offset** | Option<**String**> | offset is a numeric offset that can be used when key is unavailable. It is less efficient than using key. Only one of offset or key should be set. |  |
**pagination_period_limit** | Option<**String**> | limit is the total number of results to be returned in the result page. If left empty it will default to a value to be set by each app. |  |
**pagination_period_count_total** | Option<**bool**> | count_total is set to true  to indicate that the result set should include a count of the total number of items available for pagination in UIs. count_total is only respected when offset is used. It is ignored when key is set. |  |
**pagination_period_reverse** | Option<**bool**> | reverse is set to true if results are to be returned in the descending order.  Since: cosmos-sdk 0.43 |  |

### Return type

[**crate::models::RedelegationsResponse**](Redelegations_response.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: */*

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)


## registration_key

> crate::models::RegistrationKeyResponse registration_key()
Returns the key used for registration

### Parameters

This endpoint does not need any parameter.

### Return type

[**crate::models::RegistrationKeyResponse**](RegistrationKey_response.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: */*

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)


## restake_threshold

> crate::models::RestakeThresholdResponse restake_threshold()
RestakeThreshold queries the community pool coins.

### Parameters

This endpoint does not need any parameter.

### Return type

[**crate::models::RestakeThresholdResponse**](RestakeThreshold_response.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: */*

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)


## restaking_entries

> crate::models::RestakingEntriesResponse restaking_entries(delegator)
RestakeThreshold queries the community pool coins.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**delegator** | Option<**String**> |  |  |

### Return type

[**crate::models::RestakingEntriesResponse**](RestakingEntries_response.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: */*

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)


## router_params

> crate::models::RouterParamsResponse router_params()
Params queries all parameters of the router module.

### Parameters

This endpoint does not need any parameter.

### Return type

[**crate::models::RouterParamsResponse**](RouterParams_response.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: */*

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)


## signing_info

> crate::models::QuerySigningInfoResponseIsTheResponseTypeForTheQuerySigningInfoRpcMethod signing_info(cons_address)
SigningInfo queries the signing info of given cons address

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**cons_address** | **String** | cons_address is the address to query signing info of | [required] |

### Return type

[**crate::models::QuerySigningInfoResponseIsTheResponseTypeForTheQuerySigningInfoRpcMethod**](QuerySigningInfoResponse_is_the_response_type_for_the_Query_SigningInfo_RPC_method.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: */*

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)


## signing_infos

> crate::models::QuerySigningInfosResponseIsTheResponseTypeForTheQuerySigningInfosRpcMethod signing_infos(pagination_period_key, pagination_period_offset, pagination_period_limit, pagination_period_count_total, pagination_period_reverse)
SigningInfos queries signing info of all validators

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**pagination_period_key** | Option<**String**> | key is a value returned in PageResponse.next_key to begin querying the next page most efficiently. Only one of offset or key should be set. |  |
**pagination_period_offset** | Option<**String**> | offset is a numeric offset that can be used when key is unavailable. It is less efficient than using key. Only one of offset or key should be set. |  |
**pagination_period_limit** | Option<**String**> | limit is the total number of results to be returned in the result page. If left empty it will default to a value to be set by each app. |  |
**pagination_period_count_total** | Option<**bool**> | count_total is set to true  to indicate that the result set should include a count of the total number of items available for pagination in UIs. count_total is only respected when offset is used. It is ignored when key is set. |  |
**pagination_period_reverse** | Option<**bool**> | reverse is set to true if results are to be returned in the descending order.  Since: cosmos-sdk 0.43 |  |

### Return type

[**crate::models::QuerySigningInfosResponseIsTheResponseTypeForTheQuerySigningInfosRpcMethod**](QuerySigningInfosResponse_is_the_response_type_for_the_Query_SigningInfos_RPC_method.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: */*

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)


## simulate

> crate::models::SimulateResponse simulate(simulate_request)
Simulate simulates executing a transaction for estimating gas usage.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**simulate_request** | [**SimulateRequest**](SimulateRequest.md) |  | [required] |

### Return type

[**crate::models::SimulateResponse**](Simulate_response.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: */*

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)


## slashing_params

> crate::models::QueryParamsResponseIsTheResponseTypeForTheQueryParamsRpcMethod slashing_params()
Params queries the parameters of slashing module

### Parameters

This endpoint does not need any parameter.

### Return type

[**crate::models::QueryParamsResponseIsTheResponseTypeForTheQueryParamsRpcMethod**](QueryParamsResponse_is_the_response_type_for_the_Query_Params_RPC_method.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: */*

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)


## spendable_balances

> crate::models::SpendableBalancesResponse spendable_balances(address, pagination_period_key, pagination_period_offset, pagination_period_limit, pagination_period_count_total, pagination_period_reverse)
SpendableBalances queries the spenable balance of all coins for a single account.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**address** | **String** | address is the address to query spendable balances for. | [required] |
**pagination_period_key** | Option<**String**> | key is a value returned in PageResponse.next_key to begin querying the next page most efficiently. Only one of offset or key should be set. |  |
**pagination_period_offset** | Option<**String**> | offset is a numeric offset that can be used when key is unavailable. It is less efficient than using key. Only one of offset or key should be set. |  |
**pagination_period_limit** | Option<**String**> | limit is the total number of results to be returned in the result page. If left empty it will default to a value to be set by each app. |  |
**pagination_period_count_total** | Option<**bool**> | count_total is set to true  to indicate that the result set should include a count of the total number of items available for pagination in UIs. count_total is only respected when offset is used. It is ignored when key is set. |  |
**pagination_period_reverse** | Option<**bool**> | reverse is set to true if results are to be returned in the descending order.  Since: cosmos-sdk 0.43 |  |

### Return type

[**crate::models::SpendableBalancesResponse**](SpendableBalances_response.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: */*

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)


## staking_params

> crate::models::StakingParamsResponse staking_params()
Parameters queries the staking parameters.

### Parameters

This endpoint does not need any parameter.

### Return type

[**crate::models::StakingParamsResponse**](StakingParams_response.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: */*

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)


## supply_of

> crate::models::SupplyOfResponse supply_of(denom)
SupplyOf queries the supply of a single coin.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**denom** | **String** | denom is the coin denom to query balances for. | [required] |

### Return type

[**crate::models::SupplyOfResponse**](SupplyOf_response.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: */*

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)


## tally_result

> crate::models::TallyResultResponse tally_result(proposal_id)
TallyResult queries the tally of a proposal vote.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**proposal_id** | **String** | proposal_id defines the unique id of the proposal. | [required] |

### Return type

[**crate::models::TallyResultResponse**](TallyResult_response.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: */*

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)


## total_ack_fees

> crate::models::QueryTotalAckFeesResponseDefinesTheResponseTypeForTheTotalAckFeesRpc total_ack_fees(packet_id_period_channel_id, packet_id_period_port_id, packet_id_period_sequence)
TotalAckFees returns the total acknowledgement fees for a packet given its identifier

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**packet_id_period_channel_id** | **String** | channel unique identifier | [required] |
**packet_id_period_port_id** | **String** | channel port identifier | [required] |
**packet_id_period_sequence** | **String** | packet sequence | [required] |

### Return type

[**crate::models::QueryTotalAckFeesResponseDefinesTheResponseTypeForTheTotalAckFeesRpc**](QueryTotalAckFeesResponse_defines_the_response_type_for_the_TotalAckFees_rpc.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: */*

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)


## total_recv_fees

> crate::models::QueryTotalRecvFeesResponseDefinesTheResponseTypeForTheTotalRecvFeesRpc total_recv_fees(packet_id_period_channel_id, packet_id_period_port_id, packet_id_period_sequence)
TotalRecvFees returns the total receive fees for a packet given its identifier

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**packet_id_period_channel_id** | **String** | channel unique identifier | [required] |
**packet_id_period_port_id** | **String** | channel port identifier | [required] |
**packet_id_period_sequence** | **String** | packet sequence | [required] |

### Return type

[**crate::models::QueryTotalRecvFeesResponseDefinesTheResponseTypeForTheTotalRecvFeesRpc**](QueryTotalRecvFeesResponse_defines_the_response_type_for_the_TotalRecvFees_rpc.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: */*

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)


## total_supply

> crate::models::QueryTotalSupplyResponseIsTheResponseTypeForTheQueryTotalSupplyRpcMethod total_supply(pagination_period_key, pagination_period_offset, pagination_period_limit, pagination_period_count_total, pagination_period_reverse)
TotalSupply queries the total supply of all coins.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**pagination_period_key** | Option<**String**> | key is a value returned in PageResponse.next_key to begin querying the next page most efficiently. Only one of offset or key should be set. |  |
**pagination_period_offset** | Option<**String**> | offset is a numeric offset that can be used when key is unavailable. It is less efficient than using key. Only one of offset or key should be set. |  |
**pagination_period_limit** | Option<**String**> | limit is the total number of results to be returned in the result page. If left empty it will default to a value to be set by each app. |  |
**pagination_period_count_total** | Option<**bool**> | count_total is set to true  to indicate that the result set should include a count of the total number of items available for pagination in UIs. count_total is only respected when offset is used. It is ignored when key is set. |  |
**pagination_period_reverse** | Option<**bool**> | reverse is set to true if results are to be returned in the descending order.  Since: cosmos-sdk 0.43 |  |

### Return type

[**crate::models::QueryTotalSupplyResponseIsTheResponseTypeForTheQueryTotalSupplyRpcMethod**](QueryTotalSupplyResponse_is_the_response_type_for_the_Query_TotalSupply_RPC_method.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: */*

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)


## total_timeout_fees

> crate::models::QueryTotalTimeoutFeesResponseDefinesTheResponseTypeForTheTotalTimeoutFeesRpc total_timeout_fees(packet_id_period_channel_id, packet_id_period_port_id, packet_id_period_sequence)
TotalTimeoutFees returns the total timeout fees for a packet given its identifier

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**packet_id_period_channel_id** | **String** | channel unique identifier | [required] |
**packet_id_period_port_id** | **String** | channel port identifier | [required] |
**packet_id_period_sequence** | **String** | packet sequence | [required] |

### Return type

[**crate::models::QueryTotalTimeoutFeesResponseDefinesTheResponseTypeForTheTotalTimeoutFeesRpc**](QueryTotalTimeoutFeesResponse_defines_the_response_type_for_the_TotalTimeoutFees_rpc.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: */*

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)


## transfer_params

> crate::models::TransferParamsResponse transfer_params()
Params queries all parameters of the ibc-transfer module.

### Parameters

This endpoint does not need any parameter.

### Return type

[**crate::models::TransferParamsResponse**](TransferParams_response.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: */*

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)


## tx_key

> crate::models::RegistrationKeyResponse tx_key()
Returns the key used for transactions

### Parameters

This endpoint does not need any parameter.

### Return type

[**crate::models::RegistrationKeyResponse**](RegistrationKey_response.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: */*

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)


## unbonding_delegation

> crate::models::UnbondingDelegationResponse unbonding_delegation(validator_addr, delegator_addr)
UnbondingDelegation queries unbonding info for given validator delegator pair.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**validator_addr** | **String** | validator_addr defines the validator address to query for. | [required] |
**delegator_addr** | **String** | delegator_addr defines the delegator address to query for. | [required] |

### Return type

[**crate::models::UnbondingDelegationResponse**](UnbondingDelegation_response.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: */*

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)


## unreceived_acks

> crate::models::QueryUnreceivedAcksResponseIsTheResponseTypeForTheQueryUnreceivedAcksRpcMethod unreceived_acks(channel_id, port_id, packet_ack_sequences)
UnreceivedAcks returns all the unreceived IBC acknowledgements associated with a channel and sequences.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**channel_id** | **String** | channel unique identifier | [required] |
**port_id** | **String** | port unique identifier | [required] |
**packet_ack_sequences** | [**Vec<String>**](String.md) | list of acknowledgement sequences | [required] |

### Return type

[**crate::models::QueryUnreceivedAcksResponseIsTheResponseTypeForTheQueryUnreceivedAcksRpcMethod**](QueryUnreceivedAcksResponse_is_the_response_type_for_the_Query_UnreceivedAcks_RPC_method.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: */*

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)


## unreceived_packets

> crate::models::QueryUnreceivedPacketsResponseIsTheResponseTypeForTheQueryUnreceivedPacketCommitmentsRpcMethod unreceived_packets(channel_id, port_id, packet_commitment_sequences)
UnreceivedPackets returns all the unreceived IBC packets associated with a channel and sequences.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**channel_id** | **String** | channel unique identifier | [required] |
**port_id** | **String** | port unique identifier | [required] |
**packet_commitment_sequences** | [**Vec<String>**](String.md) | list of packet sequences | [required] |

### Return type

[**crate::models::QueryUnreceivedPacketsResponseIsTheResponseTypeForTheQueryUnreceivedPacketCommitmentsRpcMethod**](QueryUnreceivedPacketsResponse_is_the_response_type_for_the_Query_UnreceivedPacketCommitments_RPC_method.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: */*

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)


## upgraded_client_state

> crate::models::UpgradedClientStateResponse upgraded_client_state()
UpgradedClientState queries an Upgraded IBC light client.

### Parameters

This endpoint does not need any parameter.

### Return type

[**crate::models::UpgradedClientStateResponse**](UpgradedClientState_response.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: */*

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)


## upgraded_consensus_state

> crate::models::UpgradedConsensusStateResponse upgraded_consensus_state()
UpgradedConsensusState queries an Upgraded IBC consensus state.

### Parameters

This endpoint does not need any parameter.

### Return type

[**crate::models::UpgradedConsensusStateResponse**](UpgradedConsensusState_response.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: */*

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)


## upgraded_consensus_state_last_height

> crate::models::UpgradedConsensusStateLastHeightResponse upgraded_consensus_state_last_height(last_height)
UpgradedConsensusState queries the consensus state that will serve as a trusted kernel for the next version of this chain. It will only be stored at the last height of this chain. UpgradedConsensusState RPC not supported with legacy querier This rpc is deprecated now that IBC has its own replacement (https://github.com/cosmos/ibc-go/blob/2c880a22e9f9cc75f62b527ca94aa75ce1106001/proto/ibc/core/client/v1/query.proto#L54)

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**last_height** | **String** | last height of the current chain must be sent in request as this is the height under which next consensus state is stored | [required] |

### Return type

[**crate::models::UpgradedConsensusStateLastHeightResponse**](UpgradedConsensusStateLastHeight_response.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: */*

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)


## validator

> crate::models::QueryValidatorResponseIsResponseTypeForTheQueryValidatorRpcMethod validator(validator_addr)
Validator queries validator info for given validator address.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**validator_addr** | **String** | validator_addr defines the validator address to query for. | [required] |

### Return type

[**crate::models::QueryValidatorResponseIsResponseTypeForTheQueryValidatorRpcMethod**](QueryValidatorResponse_is_response_type_for_the_Query_Validator_RPC_method.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: */*

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)


## validator_commission

> crate::models::QueryValidatorCommissionResponseIsTheResponseTypeForTheQueryValidatorCommissionRpcMethod validator_commission(validator_address)
ValidatorCommission queries accumulated commission for a validator.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**validator_address** | **String** | validator_address defines the validator address to query for. | [required] |

### Return type

[**crate::models::QueryValidatorCommissionResponseIsTheResponseTypeForTheQueryValidatorCommissionRpcMethod**](QueryValidatorCommissionResponse_is_the_response_type_for_the_Query_ValidatorCommission_RPC_method.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: */*

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)


## validator_delegations

> crate::models::QueryValidatorDelegationsResponseIsResponseTypeForTheQueryValidatorDelegationsRpcMethod validator_delegations(validator_addr, pagination_period_key, pagination_period_offset, pagination_period_limit, pagination_period_count_total, pagination_period_reverse)
ValidatorDelegations queries delegate info for given validator.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**validator_addr** | **String** | validator_addr defines the validator address to query for. | [required] |
**pagination_period_key** | Option<**String**> | key is a value returned in PageResponse.next_key to begin querying the next page most efficiently. Only one of offset or key should be set. |  |
**pagination_period_offset** | Option<**String**> | offset is a numeric offset that can be used when key is unavailable. It is less efficient than using key. Only one of offset or key should be set. |  |
**pagination_period_limit** | Option<**String**> | limit is the total number of results to be returned in the result page. If left empty it will default to a value to be set by each app. |  |
**pagination_period_count_total** | Option<**bool**> | count_total is set to true  to indicate that the result set should include a count of the total number of items available for pagination in UIs. count_total is only respected when offset is used. It is ignored when key is set. |  |
**pagination_period_reverse** | Option<**bool**> | reverse is set to true if results are to be returned in the descending order.  Since: cosmos-sdk 0.43 |  |

### Return type

[**crate::models::QueryValidatorDelegationsResponseIsResponseTypeForTheQueryValidatorDelegationsRpcMethod**](QueryValidatorDelegationsResponse_is_response_type_for_the_Query_ValidatorDelegations_RPC_method.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: */*

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)


## validator_outstanding_rewards

> crate::models::ValidatorOutstandingRewardsResponse validator_outstanding_rewards(validator_address)
ValidatorOutstandingRewards queries rewards of a validator address.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**validator_address** | **String** | validator_address defines the validator address to query for. | [required] |

### Return type

[**crate::models::ValidatorOutstandingRewardsResponse**](ValidatorOutstandingRewards_response.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: */*

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)


## validator_slashes

> crate::models::ValidatorSlashesResponse validator_slashes(validator_address, starting_height, ending_height, pagination_period_key, pagination_period_offset, pagination_period_limit, pagination_period_count_total, pagination_period_reverse)
ValidatorSlashes queries slash events of a validator.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**validator_address** | **String** | validator_address defines the validator address to query for. | [required] |
**starting_height** | Option<**String**> | starting_height defines the optional starting height to query the slashes. |  |
**ending_height** | Option<**String**> | starting_height defines the optional ending height to query the slashes. |  |
**pagination_period_key** | Option<**String**> | key is a value returned in PageResponse.next_key to begin querying the next page most efficiently. Only one of offset or key should be set. |  |
**pagination_period_offset** | Option<**String**> | offset is a numeric offset that can be used when key is unavailable. It is less efficient than using key. Only one of offset or key should be set. |  |
**pagination_period_limit** | Option<**String**> | limit is the total number of results to be returned in the result page. If left empty it will default to a value to be set by each app. |  |
**pagination_period_count_total** | Option<**bool**> | count_total is set to true  to indicate that the result set should include a count of the total number of items available for pagination in UIs. count_total is only respected when offset is used. It is ignored when key is set. |  |
**pagination_period_reverse** | Option<**bool**> | reverse is set to true if results are to be returned in the descending order.  Since: cosmos-sdk 0.43 |  |

### Return type

[**crate::models::ValidatorSlashesResponse**](ValidatorSlashes_response.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: */*

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)


## validator_unbonding_delegations

> crate::models::ValidatorUnbondingDelegationsResponse validator_unbonding_delegations(validator_addr, pagination_period_key, pagination_period_offset, pagination_period_limit, pagination_period_count_total, pagination_period_reverse)
ValidatorUnbondingDelegations queries unbonding delegations of a validator.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**validator_addr** | **String** | validator_addr defines the validator address to query for. | [required] |
**pagination_period_key** | Option<**String**> | key is a value returned in PageResponse.next_key to begin querying the next page most efficiently. Only one of offset or key should be set. |  |
**pagination_period_offset** | Option<**String**> | offset is a numeric offset that can be used when key is unavailable. It is less efficient than using key. Only one of offset or key should be set. |  |
**pagination_period_limit** | Option<**String**> | limit is the total number of results to be returned in the result page. If left empty it will default to a value to be set by each app. |  |
**pagination_period_count_total** | Option<**bool**> | count_total is set to true  to indicate that the result set should include a count of the total number of items available for pagination in UIs. count_total is only respected when offset is used. It is ignored when key is set. |  |
**pagination_period_reverse** | Option<**bool**> | reverse is set to true if results are to be returned in the descending order.  Since: cosmos-sdk 0.43 |  |

### Return type

[**crate::models::ValidatorUnbondingDelegationsResponse**](ValidatorUnbondingDelegations_response.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: */*

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)


## validators

> crate::models::QueryValidatorsResponseIsResponseTypeForTheQueryValidatorsRpcMethod validators(status, pagination_period_key, pagination_period_offset, pagination_period_limit, pagination_period_count_total, pagination_period_reverse)
Validators queries all validators that match the given status.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**status** | Option<**String**> | status enables to query for validators matching a given status. |  |
**pagination_period_key** | Option<**String**> | key is a value returned in PageResponse.next_key to begin querying the next page most efficiently. Only one of offset or key should be set. |  |
**pagination_period_offset** | Option<**String**> | offset is a numeric offset that can be used when key is unavailable. It is less efficient than using key. Only one of offset or key should be set. |  |
**pagination_period_limit** | Option<**String**> | limit is the total number of results to be returned in the result page. If left empty it will default to a value to be set by each app. |  |
**pagination_period_count_total** | Option<**bool**> | count_total is set to true  to indicate that the result set should include a count of the total number of items available for pagination in UIs. count_total is only respected when offset is used. It is ignored when key is set. |  |
**pagination_period_reverse** | Option<**bool**> | reverse is set to true if results are to be returned in the descending order.  Since: cosmos-sdk 0.43 |  |

### Return type

[**crate::models::QueryValidatorsResponseIsResponseTypeForTheQueryValidatorsRpcMethod**](QueryValidatorsResponse_is_response_type_for_the_Query_Validators_RPC_method.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: */*

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)


## vote

> crate::models::VoteResponse vote(proposal_id, voter)
Vote queries voted information based on proposalID, voterAddr.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**proposal_id** | **String** | proposal_id defines the unique id of the proposal. | [required] |
**voter** | **String** | voter defines the oter address for the proposals. | [required] |

### Return type

[**crate::models::VoteResponse**](Vote_response.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: */*

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)


## votes

> crate::models::VotesResponse votes(proposal_id, pagination_period_key, pagination_period_offset, pagination_period_limit, pagination_period_count_total, pagination_period_reverse)
Votes queries votes of a given proposal.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**proposal_id** | **String** | proposal_id defines the unique id of the proposal. | [required] |
**pagination_period_key** | Option<**String**> | key is a value returned in PageResponse.next_key to begin querying the next page most efficiently. Only one of offset or key should be set. |  |
**pagination_period_offset** | Option<**String**> | offset is a numeric offset that can be used when key is unavailable. It is less efficient than using key. Only one of offset or key should be set. |  |
**pagination_period_limit** | Option<**String**> | limit is the total number of results to be returned in the result page. If left empty it will default to a value to be set by each app. |  |
**pagination_period_count_total** | Option<**bool**> | count_total is set to true  to indicate that the result set should include a count of the total number of items available for pagination in UIs. count_total is only respected when offset is used. It is ignored when key is set. |  |
**pagination_period_reverse** | Option<**bool**> | reverse is set to true if results are to be returned in the descending order.  Since: cosmos-sdk 0.43 |  |

### Return type

[**crate::models::VotesResponse**](Votes_response.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: */*

[Back to top](#) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to Model list](../README.md#documentation-for-models) [Back to README](../README.md)

