# Early Data or 0-RTT Data

TLS1.3 introduced the ability for clients to send data before completing the handshake when using external pre-shared keys or session resumption.

**WARNING:** Early data does not have the same security properties as regular data sent after a successful handshake.
* It is not forward secret. If the PSK or session resumption secret is compromised, then the early data is also compromised.
* It is susceptible to replay attacks unless proper precautions are taken. Early data can be captured and successfully resent by an attacker. See [the TLS1.3 RFC section on replay attacks](https://tools.ietf.org/rfc/rfc8446#appendix-E.5) for more details, and [Adding anti-replay protection](#adding-anti-replay-protection) for how to implement counter measures.

_**Do not enable early data for your application unless you have understood and mitigated the risks.**_

## Configuring Session Resumption for Early Data

To use early data with session tickets, early data must be enabled on a server by setting the maximum early data allowed to a non-zero value with `s2n_config_set_server_max_early_data_size()` or `s2n_connection_set_server_max_early_data_size()`. The server then begins issuing tickets that support early data, and clients can use early data when they use those tickets.

## Configuring External Pre-shared Keys for Early Data

To use early data with pre-shared keys, individual pre-shared keys must support early data. In addition to configuring the maximum early data allowed, each pre-shared key needs an associated cipher suite and if applicable, application protocol. The server only accepts early data if the pre-shared key's associated cipher suite and application protocol match the cipher suite and the application protocol negotiated during the handshake.

The maximum early data allowed and cipher suite can be set with `s2n_psk_configure_early_data()`. If the connection will negotiate an application protocol then the expected application protocol can be set with `s2n_psk_set_application_protocol()`.

## Sending Early Data

To send early data, your application should call `s2n_send_early_data()` before it calls `s2n_negotiate()`.

`s2n_connection_get_remaining_early_data_size()` can be called to check how much more early data the client is allowed to send. If `s2n_send_early_data()` exceeds the allowed maximum, s2n-tls returns a usage error.

Like other IO functions, `s2n_send_early_data()` can potentially fail repeatedly with a blocking error before it eventually succeeds: see [I/O Functions](./ch07-io.md) for more information. An application can stop calling `s2n_send_early_data()` at any time, even if the function has not returned success yet. If `s2n_send_early_data()` does return success, the connection is ready to complete the handshake and begin sending normal data. However, `s2n_send_early_data()` can continue to be called to send more early data if desired.

Once a client finishes sending early data, you should call `s2n_negotiate()` to complete the handshake just as you would for a handshake that did not include early data.

For example:
```
uint8_t early_data[] = "early data to send";
ssize_t total_data_sent = 0, len = sizeof(early_data);
while (total_data_sent < len) {
    ssize_t data_sent = 0;
    int r = s2n_send_early_data(client_conn, early_data + total_data_sent,
            len - total_data_sent, &data_sent, &blocked);
    total_data_sent += data_sent;
    if (r == S2N_SUCCESS) {
        break;
    } else if (s2n_error_get_type(s2n_errno) != S2N_ERR_T_BLOCKED) {
        exit(1);
    }
}
while (s2n_negotiate(client_conn, &blocked) != S2N_SUCCESS) {
    if (s2n_error_get_type(s2n_errno) != S2N_ERR_T_BLOCKED) {
        exit(1);
    }
}
```

## Receiving Early Data

To receive early data, your application should call `s2n_recv_early_data()` before it calls `s2n_negotiate()`.

Like other S2N IO functions, `s2n_recv_early_data()` can potentially fail repeatedly with a blocking error before it eventually succeeds: see [I/O Functions](./ch07-io.md) for more information. Once `s2n_recv_early_data()` has been called, it must be called until it returns success. If an application stops calling `s2n_recv_early_data()` early, some early data may be left unread and cause later calls to `s2n_negotiate()` to return fatal errors. Calling `s2n_recv_early_data()` again after it returns success is possible but has no effect on the connection.

Once a server has read all early data, you should call `s2n_negotiate()` to complete the handshake just as you would for a handshake that did not include early data.

For example:
```
uint8_t early_data[MAX_EARLY_DATA] = { 0 };
ssize_t total_data_recv = 0, data_recv = 0;
while (s2n_recv_early_data(conn, early_data + total_data_recv, MAX_EARLY_DATA - total_data_recv,
        &data_recv, &blocked) != S2N_SUCCESS) {
    total_data_recv += data_recv;
    if (s2n_error_get_type(s2n_errno) != S2N_ERR_T_BLOCKED) {
        exit(1);
    }
}
while (s2n_negotiate(conn, &blocked) != S2N_SUCCESS) {
    if (s2n_error_get_type(s2n_errno) != S2N_ERR_T_BLOCKED) {
        exit(1);
    }
}
```

## Adding Anti-replay Protection
**s2n-tls does not include anti-replay protection automatically.** Effective anti-replay protection for a multi-server application requires an external state shared by all servers. Without shared state, an attacker can capture early data originally sent to server A and successfully replay it against server B.

The TLS1.3 specification suggests two possible anti-replay solutions that a user can implement:
1. [Single-Use Tickets](https://tools.ietf.org/rfc/rfc8446#section-8.1): Valid tickets are stored in a shared database and deleted after use. `s2n_connection_get_negotiated_psk_identity_length()` and `s2n_connection_get_negotiated_psk_identity()` can be used to get the ticket identifier, or "pre-shared key identity", associated with offered early data.
2. [Client Hello Recording](https://tools.ietf.org/rfc/rfc8446#section-8.2): Instead of recording outstanding valid tickets, unique values from recent ClientHellos can be stored. The client hello message can be retrieved with `s2n_connection_get_client_hello()` and the pre-shared key identity can be retrieved with `s2n_connection_get_negotiated_psk_identity_length()` and `s2n_connection_get_negotiated_psk_identity()`, but s2n-tls does not currently provide methods to retrieve the validated binders or the ClientHello.random.

The `s2n_early_data_cb()` can be used to hook an anti-replay solution into s2n-tls. The callback can be configured by using `s2n_config_set_early_data_cb()`. Using the **s2n_offered_early_data** pointer offered by the callback, `s2n_offered_early_data_reject()` or `s2n_offered_early_data_accept()` can accept or reject the client request to use early data.

An example implementation:
```
int s2n_early_data_cb_impl(struct s2n_connection *conn, struct s2n_offered_early_data *early_data)
{
    uint16_t identity_size = 0;
    s2n_connection_get_negotiated_psk_identity_length(conn, &identity_size);
    uint8_t *identity = malloc(identity_size);
    s2n_connection_get_negotiated_psk_identity(conn, identity, identity_size);

    if (user_verify_single_use_ticket(identity)) {
        s2n_offered_early_data_accept(early_data);
    } else {
        s2n_offered_early_data_reject(early_data);
    }

    free(identity);
    return S2N_SUCCESS;
}
```

The callback can also be implemented asynchronously by returning **S2N_SUCCESS** without either accepting or rejecting the early data. The handshake will then fail with an **S2N_ERR_T_BLOCKED** error type and **s2n_blocked_status** set to **S2N_BLOCKED_ON_APPLICATION_INPUT** until `s2n_offered_early_data_reject()` or `s2n_offered_early_data_accept()` is called asynchronously.

An example asynchronous implementation:
```
void *user_accept_or_reject_early_data(void *arg)
{
    struct s2n_offered_early_data *early_data = (struct s2n_offered_early_data *) arg;
    if (user_slowly_verify_early_data(early_data)) {
        s2n_offered_early_data_accept(early_data);
    } else {
        s2n_offered_early_data_reject(early_data);
    }
    return NULL;
}

int s2n_early_data_cb_async_impl(struct s2n_connection *conn, struct s2n_offered_early_data *early_data)
{
    pthread_t thread_id;
    pthread_create(&thread_id, NULL, user_accept_or_reject_early_data, (void *) early_data);
    return S2N_SUCCESS;
}
```

`s2n_offered_early_data_get_context_length()` and `s2n_offered_early_data_get_context()` can be called to examine the optional user context associated with the early data. Unlike most s2n-tls callbacks, the context is not configured when the callback is set. Instead, the context is associated with the specific pre-shared key or session ticket used for early data. The context can be set for external pre-shared keys by calling `s2n_psk_set_early_data_context()`. For session tickets, `s2n_connection_set_server_early_data_context()` can be used to set the context the server includes on its new session tickets. Because the server needs to serialize the context when creating a new session ticket, the context is a byte buffer instead of the usual void pointer.
