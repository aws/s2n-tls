# TLS Connections

A TLS connection is a secure and encrypted channel established between two communicating peers. A TLS connection is used to send and receive data, perform TLS handshake negotiations, send alert messages, and etc. Read [TLS Connections](./ch04-connection.md) for information about connections, and [Sending and Receiving](./ch07-io.md) for io interactions. TLS connections are configured by TLS configs, which contains a collection of TLS settings. TLS configs apply rules on TLS connections by defining connection specs, such as supported certificate authorities. Read [Configuring the Connection](./ch05-config.md) for information about TLS connection and config interactions.

Users will need to create a `s2n_connection` struct to store all of the state necessary for a TLS connection. One `s2n_connection` must be created for each TCP stream. Call `s2n_connection_new()` to create a new server or client connection. Call `s2n_connection_free()` to free the memory allocated for this struct when no longer needed.

## Connection Memory

The connection struct is roughly 4KB with some variation depending on how it is configured. Maintainers of the s2n-tls library carefully consider increases to the size of the connection struct as they are aware some users are memory-constrained.

A connection struct has memory allocated specifically for the TLS handshake. Memory-constrained users can free that memory by calling `s2n_connection_free_handshake()` after the handshake is successfully negotiated. Note that the handshake memory can be reused for another connection if `s2n_connection_wipe()` is called, so freeing it may result in more memory allocations later. Additionally some functions that print information about the handshake may not produce meaningful results after the handshake memory is freed.

The input and output buffers consume the most memory on the connection after the handshake. It may not be necessary to keep these buffers allocated when a connection is in a keep-alive or idle state. Call `s2n_connection_release_buffers()` to wipe and free the `in` and `out` buffers associated with a connection to reduce memory overhead of long-lived connections.

## Connection Reuse

Connection objects can be re-used across many connections to reduce memory allocation. Calling `s2n_connection_wipe()` will wipe an individual connection's state and allow the connection object to be re-used for a new TLS connection.

## Connection Info

s2n-tls provides many methods to retrieve details about the handshake and connection, such as the parameters negotiated with the peer. For a full list, see our [doxygen guide](https://aws.github.io/s2n-tls/doxygen/).

### Protocol Version

s2n-tls provides multiple different methods to get the TLS protocol version of the connection. They should be called after the handshake has completed.
* `s2n_connection_get_actual_protocol_version()`: The actual TLS protocol version negotiated during the handshake. This is the primary value referred to as "protocol_version", and the most commonly used.
* `s2n_connection_get_server_protocol_version()`: The highest TLS protocol version the server supports.
* `s2n_connection_get_client_protocol_version()`: The highest TLS protocol version the client advertised.
