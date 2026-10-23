# TLS Record Sizes

The TLS protocol includes a record protocol, which specifies how to chunk TLS messages and
application data. A higher maximum record size has different tradeoffs than a lower
maximum record size in s2n-tls. For this reason, s2n-tls has several different APIs
for configuring this value.

## Sending data

When sending data, s2n-tls uses a default maximum record size of 8kb for historical reasons.

`s2n_connection_prefer_throughput()` can be called to increase the max record size, which
minimizes overhead. It also increases s2n-tls's memory usage.

`s2n_connection_prefer_low_latency()` can be called to decrease the max record size, which
allows the receiver to decrypt the data faster. It also decreases s2n-tls's memory usage.

`s2n_config_set_max_fragment_length()` controls the maximum plaintext fragment that can be sent.
The corresponding encrypted record carrying this fragment will be sized slightly larger than
the max_fragment_length, due to due to encryption and record protocol overhead.
This API will also change how much memory s2n-tls allocates internally.

##  Receiving data

s2n-tls may receive records containing up to 2^14 bytes of plaintext regardless of any settings
for sending data.

A client can can call `s2n_config_send_max_fragment_length()` to indicate a lower preferred
maximum plaintext size to the peer, and reduce the maximum size of TLS records sent. Specifically,
it does this through the RFC 6066 defined maximum fragment length extension, which standardizes
several maximum plaintext lengths. However, many TLS servers either ignore this extension or
handle it incorrectly, so a client should not assume that its requested maximum plaintext
fragment length will be honored.

By default, an s2n-tls server will ignore a client's requested maximum plaintext fragment length.
Call `s2n_config_accept_max_fragment_length()` to make an s2n-tls server respect a client's
maximum plaintext fragment length when sending data. This setting will not make a server reject
client records with a larger fragment size however.

If a maximum plaintext fragment length is negotiated during the connection, it will override the behavior
configured by `s2n_connection_prefer_throughput()`, `s2n_connection_prefer_low_latency()`, and
`s2n_config_set_max_fragment_length()`.

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
