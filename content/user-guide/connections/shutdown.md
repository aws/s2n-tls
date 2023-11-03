+++
title = 'Closing the connection'
date = 2023-10-23T19:03:55-07:00
draft = false
weight = 48
+++

- s2n_shutdown()
- s2n_shutdown_send()

Consider as a sub-page for connections

`s2n_shutdown()` attempts a graceful closure at the TLS layer. It does not close the
underlying transport. The call may block on either reading or writing.

`s2n_shutdown()` should be called after an error in order to ensure that s2n-tls
sends an alert to notify the peer of the failure.

`s2n_shutdown()` will discard any application data received from the peer. This
can lead to data truncation, so `s2n_shutdown_send()` may be preferred for TLS1.3
connections where the peer continues sending after the application initiates
shutdown. See [Closing the connection for writes](#closing-the-connection-for-writes)
below.

Because `s2n_shutdown()` attempts a graceful shutdown, it will not return success
unless a close_notify alert is successfully both sent and received. As a result,
`s2n_shutdown()` may fail when interacting with a non-conformant TLS implementation
or if called on a connection in a bad state.

Once `s2n_shutdown()` is complete:

* The s2n_connection handle cannot be used for reading or writing.
* The underlying transport can be closed, most likely via `shutdown()` or `close()`.
* The s2n_connection handle can be freed via `s2n_connection_free()` or reused
via `s2n_connection_wipe()`

### Closing the connection for writes

TLS1.3 supports closing the write side of a TLS connection while leaving the read
side unaffected. This indicates "end-of-data" to the peer without preventing
future reads. This feature is usually referred to as "half-close".

s2n-tls offers the `s2n_shutdown_send()` method to close the write side of
a connection. Unlike `s2n_shutdown()`, it does not wait for the peer to respond
with a close_notify alert and does not discard any incoming application data. An
application can continue to call `s2n_recv()` after a call to `s2n_shutdown_send()`.

`s2n_shutdown_send()` may still be called for earlier TLS versions, but most
TLS implementations will react by immediately discarding any pending writes and
closing the connection.

If `s2n_shutdown_send()` is used, the application should still call `s2n_shutdown()`
or wait for `s2n_recv()` to return 0 to indicate end-of-data before cleaning up
the connection or closing the read side of the underlying transport.