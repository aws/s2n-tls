# Sending and Receiving
## Basic IO setup

By default, s2n-tls sends and receives data using a provided file descriptor
(usually a socket) and the read/write system calls. The file descriptor can be set with
`s2n_connection_set_fd()`, or separate read and write file descriptors can be
set with `s2n_connection_set_read_fd()` and `s2n_connection_set_write_fd()`.
The provided file descriptor should be active and connected.

In general the application is free to configure the file descriptor as preferred,
including socket options. s2n-tls itself sets a few socket options:
* If available, TCP_QUICKACK is used during the TLS handshake
* If available and enabled via `s2n_connection_use_corked_io()`, TCP_CORK is
used during the TLS handshake. TCP_NOPUSH or TCP_NODELAY may be used if TCP_CORK
is not available.

**Important Note:**
If the read end of the pipe is closed unexpectedly, writing to the pipe will raise
a SIGPIPE signal. **s2n-tls does NOT handle SIGPIPE.** A SIGPIPE signal will cause
the process to terminate unless it is handled or ignored by the application.
See the [signal man page](https://linux.die.net/man/2/signal) for instructions on
how to handle C signals, or simply ignore the SIGPIPE signal by calling
`signal(SIGPIPE, SIG_IGN)` before calling any s2n-tls IO methods.

## Blocking or Non-Blocking?

s2n-tls supports both blocking and non-blocking I/O.
* In blocking mode, each s2n-tls I/O function will not return until it has completed
the requested IO operation.
* In non-blocking mode, s2n-tls I/O functions will immediately return, even if the socket couldn't
send or receive all the requested data. In this case, the I/O function will return `S2N_FAILURE`,
and `s2n_error_get_type()` will return `S2N_ERR_T_BLOCKED`. The I/O operation will have to be
called again in order to send or receive the remaining requested data.

Some s2n-tls I/O functions take a `blocked` argument. If an I/O function returns an
`S2N_ERR_T_BLOCKED` error, the `blocked` argument will be set to a `s2n_blocked_status` value,
indicating what s2n-tls is currently blocked on. Note that unless an I/O function returns
`S2N_FAILURE` with an `S2N_ERR_T_BLOCKED` error, the `blocked` argument is meaningless, and should
not be used in any application logic.

Servers in particular usually prefer non-blocking mode. In blocking mode, a single connection
blocks the thread while waiting for more IO. In non-blocking mode, multiple connections
can make progress by returning control while waiting for more IO using methods like
[`poll`](https://linux.die.net/man/2/poll) or [`select`](https://linux.die.net/man/2/select).

To use s2n-tls in non-blocking mode, set the underlying file descriptors as non-blocking.
For example:
```c
int flags = fcntl(fd, F_GETFL, 0);
if (flags < 0) return S2N_FAILURE;
if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) return S2N_FAILURE;
```

Note: If an application requires non-blocking IO, it likely also requires self-service blinding. See [Blinding](./ch03-error-handling.md#Blinding).

## Errors and Alerts

If the peer sends an alert, the next call to a read IO method will report **S2N_FAILURE** and
`s2n_error_get_type()` will return **S2N_ERR_T_ALERT**. The specific alert received
is available by calling `s2n_connection_get_alert()`.

In TLS1.3, all alerts are fatal. s2n-tls also treats all alerts as fatal in earlier
versions of TLS by default. `s2n_config_set_alert_behavior()` can be called to
force s2n-tls to treat pre-TLS1.3 warning alerts as not fatal, but that behavior
is not recommended unless required for compatibility. In the past, attacks against
TLS have involved manipulating the alert level to disguise fatal alerts as warnings.

If s2n-tls encounters a fatal error, the next call to a write IO method will send
a close_notify alert to the peer. Except for a few exceptions, s2n-tls does not
send specific alerts in order to avoid leaking information that could be used for
a sidechannel attack. To ensure that the alert is sent, `s2n_shutdown()` should
be called after an error.

## Performing the TLS Handshake

Before application data can be sent or received, an application must perform a handshake
to establish a TLS connection with the peer.

To perform the handshake, call `s2n_negotiate()` until it either returns **S2N_SUCCESS**
or returns **S2N_FAILURE** without a **S2N_ERR_T_BLOCKED** error.

For an example of how to perform a basic handshake, see [examples/s2n_negotiate.c](https://github.com/aws/s2n-tls/blob/main/docs/examples/s2n_negotiate.c)

## Application Data

After the TLS handshake, an application can send and receive encrypted data.

Although most s2n-tls APIs are not thread-safe, `s2n_send()` and `s2n_recv()`
may be called simultaneously from two different threads. This means that an
application may have one thread calling `s2n_send()` and one thread calling `s2n_recv()`,
but NOT multiple threads calling `s2n_recv()` or multiple threads calling `s2n_send()`.

Even if an application only intends to send data or only intends to receive data,
it should implement both send and receive in order to handle alerts and post-handshake
TLS control messages like session tickets.

### Sending Application Data

`s2n_send()` and its variants encrypt and send application data to the peer.
The sending methods return the number of bytes written and may indicate a partial
write. Partial writes are possible not just for non-blocking I/O, but also for
connections aborted while active.

A single call to `s2n_send()` may involve multiple system calls to write the
provided application data. s2n-tls breaks the application data into fixed-sized
records before encryption, then calls write for each record.
[See the record size documentation for how record size may impact performance](./ch08-record-sizes.md).

In non-blocking mode, `s2n_send()` will send data from the provided buffer and return the number of
bytes sent, as long as the socket was able to send at least 1 byte. If no bytes could be sent on the
socket, `s2n_send()` will return `S2N_FAILURE`, and `s2n_error_get_type()` will return
`S2N_ERR_T_BLOCKED`. To ensure that all the provided data gets sent, applications should continue
calling `s2n_send()` until the return values across all calls have added up to the length of the
data, or until `s2n_send()` returns an `S2N_ERR_T_BLOCKED` error. After an `S2N_ERR_T_BLOCKED`
error is returned, applications should call `s2n_send()` again only after the socket is
able to send more data. This can be determined by using methods like
[`poll`](https://linux.die.net/man/2/poll) or [`select`](https://linux.die.net/man/2/select).

Unlike OpenSSL, repeated calls to `s2n_send()` should not duplicate the original
parameters, but should update the inputs per the indication of size written. s2n-tls
will attempt to sanity check that the inputs are properly updated between calls.
Because of those sanity checks, a zero-length send call cannot be used as a flushing mechanism.

`s2n_sendv_with_offset()` behaves like `s2n_send()`, but supports vectorized buffers.
The offset input should be updated between calls to reflect the data already written.

`s2n_sendv()` also supports vectorized buffers, but assumes an offset of 0.
Because of this assumption, a caller would have to make sure that the input vectors
are updated to account for a partial write. Therefore `s2n_sendv_with_offset()`
is preferred.

For examples of how to send `data` of length `data_size` with `s2n_send()`
or `s2n_sendv_with_offset()`, see [examples/s2n_send.c](https://github.com/aws/s2n-tls/blob/main/docs/examples/s2n_send.c)

### Receiving Application Data

`s2n_recv()` reads and decrypts application data from the peer, copying it into
the application-provided output buffer. It returns the number of bytes read, and
may indicate a partial read even if blocking IO is used.
It returns "0" to indicate that the peer has shutdown the connection.

By default, `s2n_recv()` will return after reading a single TLS record. `s2n_recv()` can be called
repeatedly to read multiple records. To allow `s2n_recv()` to read multiple records with a single
call, use `s2n_config_set_recv_multi_record()`.

In non-blocking mode, `s2n_recv()` will read data into the provided buffer and return the number of
bytes read, as long as at least 1 byte was read from the socket. If no bytes could be read from the
socket, `s2n_recv()` will return `S2N_FAILURE`, and `s2n_error_get_type()` will return
`S2N_ERR_T_BLOCKED`. To ensure that all data on the socket is properly received, applications
should continue calling `s2n_recv()` until it returns an `S2N_ERR_T_BLOCKED` error. After an
`S2N_ERR_T_BLOCKED` error is returned, applications should call `s2n_recv()` again only after the
socket has received more data. This can be determined by using methods like
[`poll`](https://linux.die.net/man/2/poll) or [`select`](https://linux.die.net/man/2/select).

Unlike OpenSSL, repeated calls to `s2n_recv()` should not duplicate the original parameters,
but should update the inputs per the indication of size read.

For an example of how to read all the data sent by the peer into one buffer,
see `s2n_example_recv()` in [examples/s2n_recv.c](https://github.com/aws/s2n-tls/blob/main/docs/examples/s2n_recv.c)

For an example of how to echo any data sent by the peer,
see `s2n_example_recv_echo()` in [examples/s2n_recv.c](https://github.com/aws/s2n-tls/blob/main/docs/examples/s2n_recv.c)

`s2n_peek()` can be used to check if more application data may be returned
from `s2n_recv()` without performing another read from the file descriptor.
This is useful when using `select()` on the underlying s2n-tls file descriptor, because
a call to `s2n_recv()` may read more data into s2n-tls's internal buffer than
was requested or can fit into the application-provided output buffer. This extra
application data will be returned by the next call to `s2n_recv()`, but `select()`
will be unable to tell the application that there is more data available and that
`s2n_recv()` should be called again. An application can solve this problem by
calling `s2n_peek()` to determine if `s2n_recv()` needs to be called again.

## Closing the Connection

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

`s2n_shutdown()` may also read and decrypt multiple application data records while waiting
for the close_notify alert. This could result in calls to `s2n_shutdown()` taking a long
time to complete. If this is a problem, `s2n_shutdown_send()` may be preferrable.
See [Closing the connection for writes](#closing-the-connection-for-writes) below.

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

## Custom IO Callbacks

By default, s2n-tls sends and receives data using a provided file descriptor
(usually a socket) and the read/write system calls. To change this default behavior,
an application can implement custom send and receive methods using `s2n_connection_set_recv_cb()`
and `s2n_connection_set_send_cb()`.
The application can pass inputs (such as a file descriptor or destination buffer)
to the custom IO methods by using `s2n_connection_set_recv_ctx()` and `s2n_connection_set_send_ctx()`.
s2n-tls will call the custom IO methods with the custom context instead of calling
the default implementation.

The custom IO methods may send or receive less than the requested length. They
should return the number of bytes sent/received, or set errno and return an error code < 0.
s2n-tls will interpret errno set to EWOULDBLOCK or EAGAIN as indicating a retriable
blocking error, and set **s2n_errno** and the s2n_blocked_status appropriately.
s2n-tls will interpret a return value of 0 as a closed connection.
