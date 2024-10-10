# Misc

- break up the secret_client module
- make a trait for 'TxProcessor', that can have default implementation for anything with an inner TxServiceClient to be able to prepare and sign and broadcast transactions. The ComputeServiceClient could overload the tx decoding methods to include decryption.
