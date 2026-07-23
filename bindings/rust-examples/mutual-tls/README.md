This example shows how to configure mutual TLS (client authentication), where the server requires clients to prove their identity with a client certificate. The [server](src/bin/server.rs) sets `ClientAuthType::Required` and validates client certificates against its trust store. The [client](src/bin/client.rs) loads a certificate and private key, just like a server would, and presents them when the server requests a certificate.

After the handshake the client sends a greeting, the server responds, and the two sides perform a graceful shutdown: the server closes its side of the connection once it is done writing, the client reads the response up to end-of-stream and then closes its own side, and the server reads the client's end-of-stream. Skipping this shutdown sequence means a peer can see an unexpected end-of-stream error instead of a clean close.

Note that when client authentication is used, the server MUST implement a host name verification callback to validate the identity on the client certificate: the default behavior will likely reject all client certificates. See [Client / Mutual Authentication](../../../docs/usage-guide/topics/ch09-certificates.md#client--mutual-authentication). In this example the server only accepts client certificates issued to `www.wombat.com`.

To run this example, first start the server in one terminal
```
cargo run --bin server
```
The server prints the address it is listening on, e.g. `Listening on 127.0.0.1:9443`. Then run the client in another terminal, using that address.

### Authenticated client
```
cargo run --bin client 127.0.0.1:9443
```
```
TlsStream {
    connection: Connection {
        handshake_type: "NEGOTIATED|FULL_HANDSHAKE|CLIENT_AUTH|MIDDLEBOX_COMPAT",
        cipher_suite: "TLS_AES_128_GCM_SHA256",
        actual_protocol_version: TLS13,
        selected_key_exchange_group: "secp256r1",
        ..
    },
}
The server says: good byte from the server
```
The `CLIENT_AUTH` flag in the handshake type shows that the client proved its identity with its `www.wombat.com` certificate. The server receives the greeting over the mutually authenticated connection and both sides shut down cleanly:
```
The client says: hello from the client
Connection from 127.0.0.1:55104 closed
```

### Client without a certificate
A client that doesn't present a certificate is rejected. For example, the client from the [tokio-server-client](../tokio-server-client) example doesn't load a client certificate:
```
cargo run -p tokio-server-client --bin client -- 127.0.0.1:9443
```
The server rejects the connection:
```
Rejected connection from 127.0.0.1:55110: Server requires client certificate
```

### Client with an untrusted identity
A client certificate that chains to a trusted CA is still rejected if the host name verification callback doesn't accept its identity. The `www.kangaroo.com` certificate is issued by the same example CA, but the server only trusts `www.wombat.com`:
```
cargo run --bin client -- --cert ../certs/kangaroo-chain.pem --key ../certs/kangaroo-key.pem 127.0.0.1:9443
```
The server rejects the connection:
```
Rejected connection from 127.0.0.1:35188: Certificate is not valid for the supplied hostname
```
and the rejected client receives no response and fails with an error instead of shutting down cleanly.

Two behaviors to be aware of when experimenting with the rejected clients:
* The server's rejection errors only surface after a delay: s2n-tls "blinds" handshake failures by 10-30 seconds to protect against timing side-channels.
* The rejected TLS1.3 clients still print a successful handshake. With TLS1.3, the client considers the handshake complete before the server has validated the client certificate, and the rejection only arrives as an alert on a later read. This protocol quirk is described in [Client / Mutual Authentication](../../../docs/usage-guide/topics/ch09-certificates.md#client--mutual-authentication).
