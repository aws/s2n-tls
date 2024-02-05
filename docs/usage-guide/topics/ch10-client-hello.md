# Examining the Client Hello

## Getting a Client Hello

### From a connection
s2n-tls stores the received Client Hello and makes it available to the application. Call `s2n_connection_get_client_hello()` to get a pointer to the `s2n_client_hello` struct storing the Client Hello message. A NULL value will be returned if the connection has not yet received the Client Hello. The earliest point in the handshake when this struct is available is during the [Client Hello Callback](#client-hello-callback). The stored Client Hello message will not be available after calling `s2n_connection_free_handshake()`.

### From raw bytes
s2n-tls can parse a Client Hello from raw bytes. Call `s2n_client_hello_parse_message()`
with raw bytes representing a Client Hello message (including the message header, but excluding
the record header). The returned pointer to a `s2n_client_hello` struct behaves
the same as a pointer returned from `s2n_connection_get_client_hello()`, except
that the memory is owned by the application and must be freed with `s2n_client_hello_free()`.

## Examining the message

Call `s2n_client_hello_get_raw_message()` to retrieve the complete Client Hello message with the random bytes on it zeroed out.

Call `s2n_client_hello_get_cipher_suites()` to retrieve the list of cipher suites sent by the client.

Call `s2n_client_hello_get_session_id()` to retrieve the session ID sent by the client in the ClientHello message. Note that this value may not be the session ID eventually associated with this particular connection since the session ID can change when the server sends the Server Hello. The official session ID can be retrieved with `s2n_connection_get_session_id()`after the handshake completes.

Call `s2n_client_hello_get_extensions()` to retrieve the entire list of extensions sent in the Client Hello. Call `s2n_client_hello_get_extension_by_id()` to retrieve a specific extension. Because `s2n_client_hello_get_extension_by_id()` doesn't distinguish between zero-length extensions and missing extensions,
`s2n_client_hello_has_extension()` should be used to check for the existence of an extension.

Call `s2n_client_hello_get_supported_groups()` to retrieve the entire list of
supported groups sent by the client.

## SSLv2
s2n-tls will not negotiate SSLv2, but will accept SSLv2 ClientHellos advertising a
higher protocol version like SSLv3 or TLS1.0. This was a backwards compatibility
strategy used by some old clients when connecting to a server that might only support SSLv2.

You can determine whether an SSLv2 ClientHello was received by checking the value
of `s2n_connection_get_client_hello_version()`. If an SSLv2 ClientHello was
received, then `s2n_connection_get_client_protocol_version()` will still report
the real protocol version requested by the client.

SSLv2 ClientHellos are formatted differently than ClientHellos in later versions.
`s2n_client_hello_get_raw_message()` and `s2n_client_hello_get_cipher_suites()`
will produce differently formatted data. See the documentation for those methods
for details about proper SSLv2 ClientHello parsing.

## Client Hello Callback

Users can access the Client Hello during the handshake by setting the callback `s2n_config_set_client_hello_cb()`. A possible use-case for this is to modify the `s2n_connection` based on information in the Client Hello. This should be done carefully, as modifying the connection in response to untrusted input can be dangerous. In particular, switching from an `s2n_config` that supports TLS1.3 to one that does not opens the server up to a possible version downgrade attack.

`s2n_connection_server_name_extension_used()` MUST be invoked before exiting the callback if any of the connection properties were changed on the basis of the Server Name extension. If desired, the callback can return a negative value to make s2n-tls terminate the handshake early with a fatal handshake failure alert.

### Callback Modes

The callback can be invoked in two modes: **S2N_CLIENT_HELLO_CB_BLOCKING** or **S2N_CLIENT_HELLO_CB_NONBLOCKING**. Use `s2n_config_set_client_hello_cb_mode()` to set the desired mode.

The default mode, "blocking mode", will wait for the Client Hello callback to succeed and then continue the handshake. Use this mode for light-weight callbacks that won't slow down the handshake or block the main thread, like logging or simple configuration changes.

In contrast, "non-blocking mode" will wait for the ClientHello callback to succeed and then pause the handshake, immediately returning from s2n_negotiate with an error indicating that the handshake is blocked on application input. This allows the application to do expensive or time-consuming work like network calls outside of the callback without blocking the main thread. Only when the application calls `s2n_client_hello_cb_done()` will the handshake be able to resume.
