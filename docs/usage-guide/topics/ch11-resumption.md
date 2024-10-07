# Session Resumption
TLS handshake sessions are CPU-heavy due to the calculations involved in authenticating a certificate. These calculations can be skipped after the first connection by turning on session resumption. This mechanism stores state from the previous session and uses it to establish the next session, allowing the handshake to skip the costly authentication step while keeping the same cryptographic guarantees. The authentication step can be skipped because both the server and client will use their possession of the key from the previous session to prove who they are. We usually refer to the stored session state as a "session ticket". Note that this session ticket is encrypted by the server, so a server will have to set up an external key in order to do session resumption.

## Session Ticket Key

The key that encrypts and decrypts the session state is not related to the keys negotiated as part of the TLS handshake and has to be set by the server by calling `s2n_config_add_ticket_crypto_key()`. See [RFC5077](https://www.rfc-editor.org/rfc/rfc5077#section-5.5) for guidelines on securely generating keys.

Each key has two different expiration dates. The first expiration date signifies the time that the key can be used for both encryption and decryption. The second expiration date signifies the time that the key can be used only for decryption. This mechanism is to ensure that a session ticket can be successfully decrypted if it was encrypted by a key that was about to expire. The full lifetime of the key is therefore the encrypt-decrypt lifetime plus the decrypt-only lifetime. To alter the default key lifetime call `s2n_config_set_ticket_encrypt_decrypt_key_lifetime()` and `s2n_config_set_ticket_decrypt_key_lifetime()`.

The server will stop issuing session resumption tickets if a user doesn't set up a new key before the previous key passes through its encrypt-decrypt lifetime. Therefore it is recommended to add a new key when half of the previous key's encrypt-decrypt lifetime has passed.

## Stateless Session Resumption

In stateless session resumption the server sends a session ticket to a client after a successful handshake, and the client can send that ticket back to the server during a new connection to skip the authentication step. This mechanism allows servers to avoid storing individual state for each client, and for that reason is the preferred method for resuming a session.

Servers should call `s2n_config_set_session_tickets_onoff()` to enable stateless session resumption. Additionally the server needs to set up an encryption key using `s2n_config_add_ticket_crypto_key()`.

Clients should call `s2n_config_set_session_tickets_onoff()` to enable stateless session resumption and set a session ticket callback function using `s2n_config_set_session_ticket_cb()`, which will allow clients to receive a session ticket when it arrives. Then `s2n_connection_set_session()` should be called with that saved ticket when attempting to resume a new connection.

## Stateful Session Resumption

In stateful session resumption, also known as session caching, the server caches the session state per client and resumes a session based on the client's session ID. Note that session caching has not been implemented for > TLS1.2. If stateful session resumption is turned on and a TLS1.3 handshake is negotiated, the caching mechanism will not store that session and resumption will not be available the next time the client connects.

Servers should set the three caching callback functions: `s2n_config_set_cache_store_callback()`, `s2n_config_set_cache_retrieve_callback()`, and `s2n_config_set_cache_delete_callback()` and then call `s2n_config_set_session_cache_onoff()` to enable stateful session resumption. Session caching will not be turned on unless all three session cache callbacks are set prior to calling `s2n_config_set_session_cache_onoff()`. Additionally, the server needs to set up an encryption key using `s2n_config_add_ticket_crypto_key()`.

Clients should call `s2n_connection_get_session()` to retrieve some serialized state about the session. Then `s2n_connection_set_session()` should be called with that saved state when attempting to resume a new connection.

Any errors during the connection will result in that specific session being removed from the cache, making it unavailable for resumption. This includes an abrupt connection termination where no `close_notify` alert is received by the server. Applications must perform a graceful TLS shutdown to be able to resume a session with session caching. For more information on how to properly close connections, see [Closing the Connection](./ch07-io.md#closing-the-connection)

## Session Resumption in TLS1.2 and TLS1.3

In TLS1.2, session ticket messages are sent during the handshake and are automatically received as part of calling `s2n_negotiate()`. They will be available as soon as negotiation is complete.

In TLS1.3, session ticket messages are sent after the handshake as "post-handshake" messages, and may not be received as part of calling `s2n_negotiate()`. A s2n-tls server will send tickets immediately after the handshake, so clients can receive them by calling `s2n_recv()` immediately after the handshake completes. However, other server implementations may send their session tickets later, at any time during the connection.

Additionally, in TLS1.3, multiple session tickets may be issued for the same connection. Servers can call `s2n_config_set_initial_ticket_count()` to set the number of tickets they want to send and `s2n_connection_add_new_tickets_to_send()` to increase the number of tickets to send during a connection.

## Session Resumption Forward Secrecy

In TLS1.2, the secret stored inside the ticket is the original session's master secret. Because of this, TLS1.2 session tickets are not forward secret, meaning that compromising the resumed session's secret exposes the original session's encrypted data.

In contrast, in TLS1.3 the secret stored inside the ticket is _derived_ from the original session's master secret. The derivation uses a cryptographic operation that can't be reversed by an attacker to retrieve the original master secret. Therefore, TLS1.3 session tickets are forward secret, meaning compromising the resumed session's secret will not expose the original session's encrypted data.

## Keying Material Lifetimes in TLS1.2 and TLS1.3

In TLS1.2, a full handshake can issue a session ticket encrypted with a specific session ticket encryption key. Connections that resume using that session ticket will not issue new session tickets. Therefore, the lifetime of the original "keying material"-- meaning the lifetime of any secret derived from the original full handshake-- is limited by the lifetime of the session ticket encryption key. Applications can set the session ticket encryption key lifetime with `s2n_config_set_ticket_encrypt_decrypt_key_lifetime()`.

In TLS1.3, connections that resume using a session ticket CAN issue new session tickets. This is because TLS1.3 tickets are intended to be single-use, and each ticket contains a different secret: see [Session Resumption Forward Secrecy](#session-resumption-forward-secrecy). These new session tickets may be encrypted with newer session ticket encryption keys, allowing the original "keying material" to outlive the original session ticket encryption key. However, TLS1.3 enforces a specific separate "keying material" lifetime, which servers can configure with `s2n_connection_set_server_keying_material_lifetime()`. This effectively places a limit on how long sessions can be resumed before a new full handshake is required.
