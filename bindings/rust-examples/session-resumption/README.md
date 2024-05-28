This example demonstrates the s2n-tls [session resumption](https://aws.github.io/s2n-tls/usage-guide/ch11-resumption.html) feature. First, the client connects to the server and retrieves a session ticket. Then, the client connects to the server again, but uses the retrieved session ticket to resume the previous session.

This example also demonstrates how the application context can be used to associate arbitrary information, such as an IP address, with an s2n-tls connection. The IP address is used in this example to determine whether a particular session ticket is viable for use on a subsequent connection.

To run this example, first start the server in one terminal:
```
cargo run --bin server
```

Then run the client in another terminal:
```
cargo run --bin client
```
