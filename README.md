# Rust KMIP server and client

KMIP 1.2 client and server implementation

Supports Create, Register and Get
Supports Encrypt and Decrypt
Supports Mac and MacVerify

Overall experiment in writing a complicated server in rust.

Very much a work in progress.


# Server
cargo run -- -d -vvvv --serverCert ../test_data/server.pem --serverKey ../test_data/server.key --caFile ../test_data/ca.pem

# Client
```
cargo run -- --clientCert ../test_data/client.pem --clientKey ../test_data/client.key --caFile ../test_data/ca.pem createsymmetrickey
```


## License

Apache 2.0
