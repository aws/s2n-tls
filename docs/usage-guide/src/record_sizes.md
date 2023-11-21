# TLS Record Sizes

## Throughput vs Latency

When sending data, s2n-tls uses a default maximum record size which experimentation
has suggested provides a reasonable balance of performance and throughput.

`s2n_connection_prefer_throughput()` can be called to increase the record size, which
minimizes overhead. It also increases s2n-tls's memory usage.

`s2n_connection_prefer_low_latency()` can be called to decrease the record size, which
allows the receiver to decrypt the data faster. It also decreases s2n-tls's memory usage.

These options only affect the size of the records that s2n-tls sends, not the behavior
of the peer.

## Maximum Fragment Length

The maximum number of bytes that can be sent in a TLS record is called the "maximum fragment length",
and is set to 2^14 bytes by default. Regardless of the maximum record size that s2n-tls
uses when sending, it may receive records containing up to 2^14 bytes of plaintext.

A client can request a lower maximum fragment length by calling `s2n_config_send_max_fragment_length()`,
reducing the size of TLS records sent and providing benefits similar to `s2n_connection_prefer_low_latency()`.
However, many TLS servers either ignore these requests or handle them incorrectly, so a client should
never assume that a lower maximum fragment length will be honored. If a server accepts the requested
maximum fragment length, the client will respect that maximum when sending.

By default, an s2n-tls server will ignore a client's requested maximum fragment length.
If `s2n_config_accept_max_fragment_length()` is called, the server will respect the client's requested
maximum fragment length when sending, but will not reject client records with a larger fragment size.

If a maximum fragment length is negotiated during the connection, it will override the behavior
configured by `s2n_connection_prefer_throughput()` and `s2n_connection_prefer_low_latency()`.

## Dynamic Record Sizing

Sending smaller records at the beginning of a connection can decrease first byte latency,
particularly if TCP slow start is used.

`s2n_connection_set_dynamic_record_threshold()` can be called to initially send smaller records.
The connection will send the first **resize_threshold** bytes in records small enough to
fit in a single standard 1500 byte ethernet frame. Whenever **timeout_threshold** seconds
pass without sending data, the connection will revert to this behavior and send small records again.

Dynamic record sizing doesn't completely override `s2n_connection_prefer_throughput()`,
`s2n_connection_prefer_low_latency()`, or the negotiated maximum fragment length.
Once **resize_threshold** is hit, records return to the maximum size configured for the connection.
And if the maximum fragment length negotiated with the peer is lower than what dynamic record sizing
would normally produce, the lower value will be used.
