This example shows how to use the s2n-tls **async certificate validation callback**
to run custom certificate validation without blocking the handshake thread.

The [server](src/bin/server.rs) performs mutual TLS: it requires a client
certificate and, on top of s2n-tls's built-in chain validation, checks the
client certificate against a Certificate Revocation List (CRL). Because fetching
a CRL usually involves a network round-trip, the check is implemented as a
[`ConnectionFuture`]. While the fetch is in flight the handshake pauses without
blocking the tokio runtime, so the server can keep making progress on other
connections.

The callback of interest is `NetworkCrlFetcher`:

```rust
impl CertValidationCallback for NetworkCrlFetcher {
    fn validate_cert(&self, connection: &mut Connection, info: CertValidationInfo)
        -> Result<Option<Pin<Box<dyn ConnectionFuture>>>, Error>
    {
        // ...identify the peer certificate, then return a future that fetches
        // the CRL asynchronously and calls info.accept()/reject() when it resolves.
    }
}
```

> Note: the CRL "fetch" is simulated with an async delay so the example is
> self-contained. In production this is where you would issue a real request
> (e.g. an async HTTP GET) and parse the returned CRL. The relevant point is
> that the work is `.await`ed inside the `ConnectionFuture`, off the handshake
> thread.

The callback is registered with `set_cert_validation_callback`, which is behind
the `unstable-crl` feature (already enabled in this example's `Cargo.toml`).

## Accepted client

Start the server:
```
cargo run --bin server
```
Then connect with the client:
```
cargo run --bin client
```
The server logs the async CRL fetch and accepts the certificate:
```
fetching CRL from http://crl.example.com/clients.crl for client 0x....
client 0x.... is valid
```
and the client prints:
```
server said: Hello, your client certificate was accepted
```

## Revoked client

Restart the server so its simulated CRL revokes every client:
```
cargo run --bin server -- --revoke-all
```
The server logs the rejection:
```
client 0x.... is REVOKED
handshake rejected: Certificate failed custom application validation
```
Connect again:
```
cargo run --bin client
```
This time the callback rejects the certificate. In TLS 1.3 the client completes
its own side of the handshake before the server validates the client
certificate, so the rejection surfaces on the client when the server closes the
connection instead of sending a response:
```
client certificate rejected: server closed the connection
```
(Depending on timing this may instead appear as a `handshake failed ...`
message; the client handles both.)
