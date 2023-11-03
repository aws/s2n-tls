+++
title = 'Send and receive application data'
menuTitle = 'Send/Receive'
date = 2023-10-23T18:58:17-07:00
draft = false
weight = 42
+++

- s2n_recv()
- s2n_recv_early_data()
- s2n_recv_fn
- s2n_send()
- s2n_send_early_data()
- s2n_send_fn
- s2n_sendv()
- s2n_sendv_with_offset()
- s2n_peek()

After the TLS handshake, an application can send and receive encrypted data.

Although most s2n-tls APIs are not thread-safe, `s2n_send()` and `s2n_recv()`
may be called simultaneously from two different threads. This means that an
application may have one thread calling `s2n_send()` and one thread calling `s2n_recv()`, but NOT multiple threads calling `s2n_recv()` or multiple threads calling `s2n_send()`.

Even if an application only intends to send data or only intends to receive data,
it should implement both send and receive in order to handle alerts and post-handshake
TLS control messages like session tickets.

## Sending application data

`s2n_send()` and its variants encrypt and send application data to the peer.
The sending methods return the number of bytes written and may indicate a partial
write. Partial writes are possible not just for non-blocking I/O, but also for
connections aborted while active.

A single call to `s2n_send()` may involve multiple system calls to write the
provided application data. s2n-tls breaks the application data into fixed-sized
records before encryption, and calls write for each record.
[See the record size documentation for how record size may impact performance](https://github.com/aws/s2n-tls/blob/main/docs/USAGE-GUIDE.md#record-sizes).

In non-blocking mode, `s2n_send()` will send data from the provided buffer and return the number of bytes sent, as long as the socket was able to send at least 1 byte. If no bytes could be sent on the socket, `s2n_send()` will return `S2N_FAILURE`, and `s2n_error_get_type()` will return `S2N_ERR_T_BLOCKED`. To ensure that all the provided data gets sent, applications should continue calling `s2n_send()` until the return values across all calls have added up to the length of the data, or until `s2n_send()` returns an `S2N_ERR_T_BLOCKED` error. After an `S2N_ERR_T_BLOCKED` error is returned, applications should call `s2n_send()` again only after the socket is able to send more data. This can be determined by using methods like [`poll`](https://linux.die.net/man/2/poll) or [`select`](https://linux.die.net/man/2/select).

Unlike OpenSSL, repeated calls to `s2n_send()` should not duplicate the original parameters, but should update the inputs per the indication of size written.

`s2n_sendv_with_offset()` behaves like `s2n_send()`, but supports vectorized buffers. The offset input should be updated between calls to reflect the data already written.

`s2n_sendv()` also supports vectorized buffers, but assumes an offset of 0. Because of this assumption, a caller would have to make sure that the input vectors are updated to account for a partial write. Therefore `s2n_sendv_with_offset()` is preferred.

For examples of how to send `data` of length `data_size` with `s2n_send()` or `s2n_sendv_with_offset()`, see [examples/s2n_send.c](https://github.com/aws/s2n-tls/blob/main/docs/examples/s2n_send.c)

## Receiving application data

`s2n_recv()` reads and decrypts application data from the peer, copying it into
the application-provided output buffer. It returns the number of bytes read, and
may indicate a partial read even if blocking IO is used.
It returns "0" to indicate that the peer has shutdown the connection.

By default, `s2n_recv()` will return after reading a single TLS record. `s2n_recv()` can be called repeatedly to read multiple records. To allow `s2n_recv()` to read multiple records with a single call, use `s2n_config_set_recv_multi_record()`.

In non-blocking mode, `s2n_recv()` will read data into the provided buffer and return the number of bytes read, as long as at least 1 byte was read from the socket. If no bytes could be read from the socket, `s2n_recv()` will return `S2N_FAILURE`, and `s2n_error_get_type()` will return `S2N_ERR_T_BLOCKED`. To ensure that all data on the socket is properly received, applications should continue calling `s2n_recv()` until it returns an `S2N_ERR_T_BLOCKED` error. After an `S2N_ERR_T_BLOCKED` error is returned, applications should call `s2n_recv()` again only after the socket has received more data. This can be determined by using methods like [`poll`](https://linux.die.net/man/2/poll) or [`select`](https://linux.die.net/man/2/select).

Unlike OpenSSL, repeated calls to `s2n_recv()` should not duplicate the original parameters, but should update the inputs per the indication of size read.

For an example of how to read all the data sent by the peer into one buffer, see `s2n_example_recv()` in [examples/s2n_recv.c](https://github.com/aws/s2n-tls/blob/main/docs/examples/s2n_recv.c)

For an example of how to echo any data sent by the peer, see `s2n_example_recv_echo()` in [examples/s2n_recv.c](https://github.com/aws/s2n-tls/blob/main/docs/examples/s2n_recv.c)

`s2n_peek()` can be used to check if more application data may be returned
from `s2n_recv()` without performing another read from the file descriptor.
This is useful when using `select()` on the underlying s2n-tls file descriptor, because
a call to `s2n_recv()` may read more data into s2n-tls's internal buffer than
was requested or can fit into the application-provided output buffer. This extra
application data will be returned by the next call to `s2n_recv()`, but `select()`
will be unable to tell the application that there is more data available and that
`s2n_recv()` should be called again. An application can solve this problem by
calling `s2n_peek()` to determine if `s2n_recv()` needs to be called again.
