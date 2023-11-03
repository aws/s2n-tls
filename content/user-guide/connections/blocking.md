+++
title = 'Blocking and non-blocking connections'
date = 2023-10-23T18:57:04-07:00
draft = false
weight = 43
+++

s2n_blocked_status

s2n-tls supports both blocking and non-blocking I/O.

* In blocking mode, each s2n-tls I/O function will not return until it has completed
the requested IO operation.
* In non-blocking mode, s2n-tls I/O functions will immediately return, even if the socket couldn't send or receive all the requested data. In this case, the I/O function will return `S2N_FAILURE`,
and `s2n_error_get_type()` will return `S2N_ERR_T_BLOCKED`. The I/O operation will have to be called again in order to send or receive the remaining requested data.

Some s2n-tls I/O functions take a `blocked` argument. If an I/O function returns an
`S2N_ERR_T_BLOCKED` error, the `blocked` argument will be set to a `s2n_blocked_status` value, indicating what s2n-tls is currently blocked on. Note that unless an I/O function returns `S2N_FAILURE` with an `S2N_ERR_T_BLOCKED` error, the `blocked` argument is meaningless, and should not be used in any application logic.

Servers in particular usually prefer non-blocking mode. In blocking mode, a single connection blocks the thread while waiting for more IO. In non-blocking mode, multiple connections can make progress by returning control while waiting for more IO using methods like [`poll`](https://linux.die.net/man/2/poll) or [`select`](https://linux.die.net/man/2/select).

To use s2n-tls in non-blocking mode, set the underlying file descriptors as non-blocking. For example:

```c
int flags = fcntl(fd, F_GETFL, 0);
if (flags < 0) return S2N_FAILURE;
if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) return S2N_FAILURE;
```
