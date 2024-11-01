# Software Architecture

User interaction with s2n-tls happens primarily through the `s2n_connection` and `s2n_config` structures.

## Primary Structures

Users start by building a config. In the general case, there will be one config per server. This involves loading the certificate, configuring session resumption, etc. Users should configure an `s2n_config` before associating any `s2n_connection` objects with it.

Users must then configure a connection, and associate it with a config. `s2n_connection` is responsible for managing the actual state of a TLS connection. In a TLS server, there will be one `s2n_connection` for each TCP stream. For each `s2n_config`, there may be many `s2n_connection` structs associated with it.

## Mutability

`s2n_config` MUST NOT be mutated after it is associated with a connection, with the exception of `s2n_config_add_ticket_crypto_key`.

## Thread Safety

In general, s2n-tls APIs are not thread safe unless explicitly specified otherwise. Neither `s2n_config` nor `s2n_connection` can be configured from multiple threads. 

After being configured, `s2n_config`s MUST be treated as immutable, and therefore can be safely referenced from multiple threads. It is safe for multiple `s2n_connections` on different threads to share the same s2n_config. 

`s2n_connection`s are not immutable, and it is generally unsafe to mutate them from multiple threads. One exception is that `s2n_send` and `s2n_recv` can be called simultaneously from different threads. However it is not valid to call `s2n_send` or `s2n_recv` from multiple threads. E.g. It is invalid for two threads to simultaneously call `s2n_send`.
