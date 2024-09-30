# Message Traits

```rust
use prost::Message;
use cosmrs::{MessageExt, Msg};
use rsecret::{ToAmino, EncryptMe?};
```

Situation:

- We already have the `cosmrs::Msg` trait that handles `into_any` and `into_proto`.
- We need to add a way to encode every message type `to_amino`.
- I can't change the `cosmrs::Msg` trait. I need to add another trait `ToAmino` for that, and implement it for each of the message types in cosmrs/secrers.
- In order to support broadcasting a `Vec<impl Msg>`, each message must already be encrypted.
- In order to encrypt messages, they need the code_hash.
- The secretrs message types do not have a code_hash field.
- Perhaps I can add another trait to only `MsgExecuteContract`, `MsgInstantiateContract`, and `MsgMigrateContract` that would add `encrypt` and `decrypt` methods. A user would have to encrypt those messages before including them in the list of messages to be broadcast, and they can do that by giving the code hash (and EncryptionUtils?).
- That trait can have an associated type of EncryptionUtils? But how does it know which EncryptionUtils to use...?

```rust
// msg is the serde_json::to_vec version of the message
let message = MsgExecuteContract { sender, contract, msg, sent_funds }.encrypt(code_hash);
```
