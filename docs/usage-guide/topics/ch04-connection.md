# TLS Connections

In general, s2n-tls works by operating on `s2n_connection` structs. A user should first create a connection by calling `s2n_connection_new()`. Then a [TLS handshake can be performed](./ch07-io.md#performing-the-tls-handshake) on the connection. Finally, the connection can be used to [send and receive encrypted data](./ch07-io.md#application-data). An `s2n_config` struct can be associated with a connection to provide [configuration outside of the default](./ch05-config.md).

Call `s2n_connection_free()` to free the memory allocated for connection when no longer needed.

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
