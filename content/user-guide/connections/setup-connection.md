+++
title = 'Setup Connection'
date = 2023-10-27T20:08:58-07:00
weight = 41
draft = false
+++

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

## Performing the TLS handshake

Before application data can be sent or received, an application must perform a handshake
to establish a TLS connection with the peer.

To perform the handshake, call `s2n_negotiate()` until it either returns **S2N_SUCCESS**
or returns **S2N_FAILURE** without a **S2N_ERR_T_BLOCKED** error.

For an example of how to perform a basic handshake, see [examples/s2n_negotiate.c](https://github.com/aws/s2n-tls/blob/main/docs/examples/s2n_negotiate.c)

## Custom IO callbacks

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
