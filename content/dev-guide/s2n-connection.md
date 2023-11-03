+++
title = 'TLS state machine'
date = 2023-10-27T13:45:16-07:00
weight = 50
draft = false
+++

> [!NOTE]
> This is a good explanation and it might be helpful to a lot of people.
> Consider moving it to the Connections section of the user guide

Every connection is associated with an s2n_connection structure. The details of this structure are opaque to applications, but internally it is where all of the TLS state is managed. To make sense of what is going on, it is necessary to understand how the TLS protocol works at the record and handshake layers.

When a TLS connection is being started, the first communication consists of handshake messages. The client sends the first message (a client hello), and then the server replies (with a server hello), and so on. Because a server must wait for a client and vice versa, this phase of a TLS connection is not full-duplex. To save on memory, s2n-tls uses a single stuffer for both incoming and outgoing handshake messages and it is located as s2n_connection->handshake.io (which is a growable stuffer).

Borrowing another trick from functional programming, the state machine for handling handshake messages is implemented using a table of function pointers, located in [tls/s2n_handshake_io.c](https://github.com/aws/s2n-tls/blob/main/tls/s2n_handshake_io.c).

```c
static struct s2n_handshake_action state_machine[] = {
    /*Message type  Handshake type       Writer S2N_SERVER                S2N_CLIENT                   handshake.state              */
    {TLS_HANDSHAKE, TLS_CLIENT_HELLO,      'C', {s2n_client_hello_recv,    s2n_client_hello_send}},    /* CLIENT_HELLO              */
    {TLS_HANDSHAKE, TLS_SERVER_HELLO,      'S', {s2n_server_hello_send,    s2n_server_hello_recv}},    /* SERVER_HELLO              */
    {TLS_HANDSHAKE, TLS_SERVER_CERT,       'S', {s2n_server_cert_send,     s2n_server_cert_recv}},     /* SERVER_CERT               */
    {TLS_HANDSHAKE, TLS_SERVER_KEY,        'S', {s2n_server_key_send,      s2n_server_key_recv}},      /* SERVER_KEY                */
    {TLS_HANDSHAKE, TLS_SERVER_CERT_REQ,   'S', {NULL,                     NULL}},                     /* SERVER_CERT_REQ           */
    {TLS_HANDSHAKE, TLS_SERVER_HELLO_DONE, 'S', {s2n_server_done_send,     s2n_server_done_recv}},     /* SERVER_HELLO_DONE         */
    {TLS_HANDSHAKE, TLS_CLIENT_CERT,       'C', {NULL,                     NULL}},                     /* CLIENT_CERT               */
    {TLS_HANDSHAKE, TLS_CLIENT_KEY,        'C', {s2n_client_key_recv,      s2n_client_key_send}},      /* CLIENT_KEY                */
    {TLS_HANDSHAKE, TLS_CLIENT_CERT_VERIFY,'C', {NULL,                     NULL}},                     /* CLIENT_CERT_VERIFY        */
    {TLS_CHANGE_CIPHER_SPEC, 0,            'C', {s2n_client_ccs_recv,      s2n_client_ccs_send}},      /* CLIENT_CHANGE_CIPHER_SPEC */
    {TLS_HANDSHAKE, TLS_CLIENT_FINISHED,   'C', {s2n_client_finished_recv, s2n_client_finished_send}}, /* CLIENT_FINISHED           */
    {TLS_CHANGE_CIPHER_SPEC, 0,            'S', {s2n_server_ccs_send,      s2n_server_ccs_recv}},      /* SERVER_CHANGE_CIPHER_SPEC */
    {TLS_HANDSHAKE, TLS_SERVER_FINISHED,   'S', {s2n_server_finished_send, s2n_server_finished_recv}}, /* SERVER_FINISHED           */
    {TLS_APPLICATION_DATA, 0,              'B', {NULL, NULL}}    /* HANDSHAKE_OVER            */
};
```

The 'writer' field indicates whether we expect a Client or a Server to write a particular message type (or 'B' for both in the case of an application data message, but we haven't gotten to that yet). If s2n-tls is acting as a server, then it attempts to read client messages, if it's acting as a client it will try to write it. To perform either operation it calls the relevant function pointer. This way the state machine can be very short and simple: write a handshake message out when we have one pending, and in the other direction read in data until we have a fully-buffered handshake message before then calling the relevant message parsing function.

One detail we've skipped over so far is that handshake messages are encapsulated by an additional record layer within the TLS protocol. As we've already seen, TLS records are fairly simple: just a 5-byte header indicating the message type (Handshake, application data, and alerts), protocol version, and record size. The remainder of the record is data and may or may not be encrypted. What isn't so simple is that TLS allows 'inner' messages, like Handshake message, to be fragmented across several records, and for a single record to contain multiple messages.

![TLS layers](images/s2n_tls_layers.png "s2n-tls TLS layers")

In the outbound direction, s2n-tls never coalesces multiple messages into a single record, so writing a handshake message is a simple matter of fragmenting the handshake message if necessary and writing the records. In the inbound direction, the small state machine in s2n_handshake_io.c takes care of any fragmentation and coalescing. See [tests/unit/s2n_fragmentation_coalescing_test.c](https://github.com/aws/s2n-tls/blob/main/tests/unit/s2n_fragmentation_coalescing_test.c) for our test cases covering the logic too.

To perform all of this, the s2n_connection structure has a few more internal stuffers:

```c
struct s2n_stuffer header_in;
struct s2n_stuffer in;
struct s2n_stuffer out;
struct s2n_stuffer alert_in;
```

'header_in' is a small 5-byte stuffer, which is used to read in a record header. Once that stuffer is full, and the size of the next record is determined (from that header), inward data is directed to the 'in' stuffer.  The 'out' stuffer is for data that we are writing out; like an encrypted TLS record. 'alert_in' is for any TLS alert message that s2n-tls receives from its peer. s2n-tls treats all alerts as fatal, but we buffer the full alert message so that reason can be logged.

When past the handshake phase, s2n-tls supports full-duplex I/O. Separate threads or event handlers are free to call s2n_send and s2n_recv on the same connection. Because either a read or a write may cause a connection to be closed, there are two additional fields for storing outbound alert messages:

```c
uint8_t reader_alert_out;
uint8_t writer_alert_out;
```

This pattern means that both the reader thread and writer thread can create pending alert messages without needing any locks. If either the reader or writer generates an alert, it also sets the 'closed' states to 1.

```c
sig_atomic_t read_closed;
sig_atomic_t write_closed;
```

These fields are atomic. However because they are only ever changed from 0 to 1, an over-write would be harmless.

s2n-tls only sends fatal alerts during `s2n_shutdown()` or `s2n_shutdown_send()`.
Only one alert is sent, so writer alerts take priority if both are present.
If no alerts are present, then a generic close_notify will be sent instead.
