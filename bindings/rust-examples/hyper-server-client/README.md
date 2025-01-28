This example demonstrates how to use s2n-tls with the [hyper](https://hyper.rs/) HTTP library.

The server example demonstrates how to use s2n-tls with the [hyper-util server](https://docs.rs/hyper-util/latest/hyper_util/server/conn/auto/struct.Builder.html). The client example demonstrates how to use s2n-tls with the [legacy hyper-util client](https://docs.rs/hyper-util/latest/hyper_util/client/legacy/struct.Builder.html), via the [s2n-tls-hyper](../../rust/standard/s2n-tls-hyper) compatibility crate.

Start the example server as follows:
```
cargo run --bin server
```

The server will listen for incoming TLS connections, and echo the contents of HTTP requests back to the client in an HTTP response.

Connect to the server with the example client as follows:
```
cargo run --bin client -- --body "some text to send to the server"
```
