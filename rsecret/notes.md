# Message Traits

```rust
use prost::Message;
use cosmrs::{MessageExt, Msg};
use rsecret::{ToAmino, Enigma2?};
```

Situation:

- We already have the `cosmrs::Msg` trait that handles `into_any` and `into_proto`.
- We need to add a way to encode every message type `to_amino`.
- I can't change the `cosmrs::Msg` trait. I need to add another trait `ToAmino` for that, and implement it for each of the message types in cosmrs/secrers.
- In order to support broadcasting a `Vec<impl Msg>`, each message must already be encrypted.
- In order to encrypt messages, they need the code_hash.
- The secretrs message types do not have a code_hash field.

# Misc

- break up the secret_network_client module
- don't have a 'traits' module; that's dumb
- make a trait for 'TxProcessor', that can have default implementation for anything with an inner TxServiceClient to be able to prepare and sign and broadcast transactions. The ComputeServiceClient could overload the tx decoding methods to include decryption.
