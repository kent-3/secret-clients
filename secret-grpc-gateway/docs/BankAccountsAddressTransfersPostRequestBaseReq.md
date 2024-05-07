# BankAccountsAddressTransfersPostRequestBaseReq

## Properties

| Name               | Type                                                                                                                      | Description                                                                       | Notes      |
| ------------------ | ------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------- | ---------- |
| **from**           | Option<**String**>                                                                                                        | Sender address or Keybase name to generate a transaction                          | [optional] |
| **memo**           | Option<**String**>                                                                                                        |                                                                                   | [optional] |
| **chain_id**       | Option<**String**>                                                                                                        |                                                                                   | [optional] |
| **account_number** | Option<**String**>                                                                                                        |                                                                                   | [optional] |
| **sequence**       | Option<**String**>                                                                                                        |                                                                                   | [optional] |
| **gas**            | Option<**String**>                                                                                                        |                                                                                   | [optional] |
| **gas_adjustment** | Option<**String**>                                                                                                        |                                                                                   | [optional] |
| **fees**           | Option<[**Vec<crate::models::TxsHashGetResponseTxFeeAmountInner>**](_txs__hash__get_response_tx_fee_amount_inner.md)> |                                                                                   | [optional] |
| **simulate**       | Option<**bool**>                                                                                                          | Estimate gas for a transaction (cannot be used in conjunction with generate_only) | [optional] |

[Back to Model list](../README.md#documentation-for-models) [Back to API list](../README.md#documentation-for-api-endpoints) [Back to README](../README.md)
