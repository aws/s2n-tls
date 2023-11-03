+++
title = 'Blinding'
date = 2023-10-23T19:54:56-07:00
draft = false
weight = 47
+++

- s2n_connection_set_blinding()
- s2n_blinding

Possibly a sub-page of connections

Blinding is a mitigation against timing side-channels which in some cases can leak information about encrypted data. By default s2n-tls will cause a thread to sleep between 10 and 30 seconds whenever tampering is detected.

Setting the `S2N_SELF_SERVICE_BLINDING` option with `s2n_connection_set_blinding()` turns off this behavior. This is useful for applications that are handling many connections in a single thread. In that case, if `s2n_recv()` or `s2n_negotiate()` return an error, self-service applications must call `s2n_connection_get_delay()` and pause activity on the connection for the specified number of nanoseconds before calling `close()` or `shutdown()`. `s2n_shutdown()` will fail if called before the blinding delay elapses.
