This example shows how to use the s2n-tls client hello callback to configure different TLS configs based on the Server Name Indication (SNI) in the client hello. The [server](src/bin/server.rs) sets up two configs for two different sni's, `www.wombat.com` and `www.kangaroo.com`. These configs are set up with different cipher preferences so that the allowed TLS versions are dependent on the client SNI.

To run this example, first start the server in one terminal
```
cargo run --bin server
```
Then run the client in another terminal, setting the appropriate SNI.

### Kangaroo SNI
```
cargo run --bin client www.kangaroo.com
```
```
TlsStream {
    connection: Connection {
        handshake_type: "NEGOTIATED|FULL_HANDSHAKE|MIDDLEBOX_COMPAT",
        cipher_suite: "TLS_AES_128_GCM_SHA256",
        actual_protocol_version: TLS13,
        selected_curve: "x25519",
        ..
    },
}
The server said Hello, you are speaking to www.kangaroo.com
```
We can see that the server successfully responded with the appropriate `www.kangaroo.com` certificate, resulting in a successful handshake.

### Wombat SNI
```
cargo run --bin client www.wombat.com
```
```
TlsStream {
    connection: Connection {
        handshake_type: "NEGOTIATED|FULL_HANDSHAKE|TLS12_PERFECT_FORWARD_SECRECY",
        cipher_suite: "ECDHE-ECDSA-AES128-SHA",
        actual_protocol_version: TLS12,
        selected_curve: "secp256r1",
        ..
    },
}
The server said Hello, you are speaking to www.wombat.com
```
Once again there is a successful handshake showing that the server responded with the proper certificate. In this case, the config that the server configured for `www.wombat.com` did not support TLS 1.3, so the TLS 1.2 was negotiated instead.

## Async Config Resolution
The [async load server](src/bin/async_load_server.rs) has the same functionality as the default [server](src/bin/server.rs), but implements the config resolution in an asynchronous manner. This allows the certificates to be loaded from disk without blocking the tokio runtime. A similar technique could be used to retrieve certificates over the network without blocking the runtime.
