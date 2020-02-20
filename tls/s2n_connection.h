/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 *  http://aws.amazon.com/apache2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

#pragma once

#include <stdint.h>
#include <signal.h>
#include <errno.h>
#include <s2n.h>

#include "tls/s2n_tls_parameters.h"
#include "tls/s2n_handshake.h"
#include "tls/s2n_client_hello.h"
#include "tls/s2n_crypto.h"
#include "tls/s2n_config.h"
#include "tls/s2n_prf.h"
#include "tls/s2n_x509_validator.h"

#include "stuffer/s2n_stuffer.h"

#include "crypto/s2n_hash.h"
#include "crypto/s2n_hmac.h"

#include "utils/s2n_timer.h"
#include "utils/s2n_mem.h"

#define S2N_TLS_PROTOCOL_VERSION_LEN    2

#define is_handshake_complete(conn) (APPLICATION_DATA == s2n_conn_get_current_message_type(conn))

typedef enum {
    S2N_NO_TICKET = 0,
    S2N_DECRYPT_TICKET,
    S2N_NEW_TICKET
} s2n_session_ticket_status;

struct s2n_connection {
    /* The configuration (cert, key .. etc ) */
    struct s2n_config *config;

    /* Overrides Cipher Preferences in config if non-null */
    const struct s2n_cipher_preferences *cipher_pref_override;

    /* The user defined context associated with connection */
    void *context;

    /* The send and receive callbacks don't have to be the same (e.g. two pipes) */
    s2n_send_fn *send;
    s2n_recv_fn *recv;

    /* The context passed to the I/O callbacks */
    void *send_io_context;
    void *recv_io_context;

    /* Has the user set their own I/O callbacks or is this connection using the
     * default socket-based I/O set by s2n */
    uint8_t managed_io;

    /* Is this connection using CORK/SO_RCVLOWAT optimizations? Only valid when the connection is using
     * managed_io
     */
    unsigned corked_io:1;

    /* Session resumption indicator on client side */
    unsigned client_session_resumed:1;

    /* Determines if we're currently sending or receiving in s2n_shutdown */
    unsigned close_notify_queued:1;

    /* s2n does not support renegotiation.
     * RFC5746 Section 4.3 suggests servers implement a minimal version of the
     * renegotiation_info extension even if renegotiation is not supported.
     * Some clients may fail the handshake if a corresponding renegotiation_info
     * extension is not sent back by the server.
     */
    unsigned secure_renegotiation:1;
    /* Was the EC point formats sent by the client */
    unsigned ec_point_formats:1;

     /* whether the connection address is ipv6 or not */
    unsigned ipv6:1;

    /* Whether server_name extension was used to make a decision on cert selection.
     * RFC6066 Section 3 states that server which used server_name to make a decision
     * on certificate or security settings has to send an empty server_name.
     */
    unsigned server_name_used:1;

    /* If write fd is broken */
    unsigned write_fd_broken:1;
    
    /* Is this connection a client or a server connection */
    s2n_mode mode;

    /* Does s2n handle the blinding, or does the application */
    s2n_blinding blinding;

    /* A timer to measure the time between record writes */
    struct s2n_timer write_timer;

    /* last written time */
    uint64_t last_write_elapsed;

    /* When fatal errors occurs, s2n imposes a pause before
     * the connection is closed. If non-zero, this value tracks
     * how many nanoseconds to pause - which will be relative to
     * the write_timer value. */
    uint64_t delay;

    /* The session id */
    uint8_t session_id[S2N_TLS_SESSION_ID_MAX_LEN];
    uint8_t session_id_len;

    /* The version advertised by the client, by the
     * server, and the actual version we are currently
     * speaking. */
    uint8_t client_hello_version;
    uint8_t client_protocol_version;
    uint8_t server_protocol_version;
    uint8_t actual_protocol_version;

    /* Flag indicating whether a protocol version has been
     * negotiated yet. */
    uint8_t actual_protocol_version_established;

    /* Our crypto parameters */
    struct s2n_crypto_parameters initial;
    struct s2n_crypto_parameters secure;

    /* Which set is the client/server actually using? */
    struct s2n_crypto_parameters *client;
    struct s2n_crypto_parameters *server;

    /* Contains parameters needed during the handshake phase */
    struct s2n_handshake_parameters handshake_params;

    /* The PRF needs some storage elements to work with */
    struct s2n_prf_working_space prf_space;

    /* Whether to use client_cert_auth_type stored in s2n_config or in this s2n_connection.
     *
     * By default the s2n_connection will defer to s2n_config->client_cert_auth_type on whether or not to use Client Auth.
     * But users can override Client Auth at the connection level using s2n_connection_set_client_auth_type() without mutating
     * s2n_config since s2n_config can be shared between multiple s2n_connections. */
    uint8_t client_cert_auth_type_overridden;

    /* Whether or not the s2n_connection should require the Client to authenticate itself to the server. Only used if
     * client_cert_auth_type_overridden is non-zero. */
    s2n_cert_auth_type client_cert_auth_type;

    /* Our workhorse stuffers, used for buffering the plaintext
     * and encrypted data in both directions.
     */
    uint8_t header_in_data[S2N_TLS_RECORD_HEADER_LENGTH];
    struct s2n_stuffer header_in;
    struct s2n_stuffer in;
    struct s2n_stuffer out;
    enum { ENCRYPTED, PLAINTEXT } in_status;

    /* How much of the current user buffer have we already
     * encrypted and sent or have pending for the wire but have
     * not acknowledged to the user.
     */
    ssize_t current_user_data_consumed;

    /* An alert may be fragmented across multiple records,
     * this stuffer is used to re-assemble.
     */
    uint8_t alert_in_data[S2N_ALERT_LENGTH];
    struct s2n_stuffer alert_in;

    /* An alert may be partially written in the outbound
     * direction, so we keep this as a small 2 byte queue.
     *
     * We keep separate queues for alerts generated by
     * readers (a response to an alert from a peer) and writers (an
     * intentional shutdown) so that the s2n reader and writer
     * can be separate duplex I/O threads.
     */
    uint8_t reader_alert_out_data[S2N_ALERT_LENGTH];
    uint8_t writer_alert_out_data[S2N_ALERT_LENGTH];
    struct s2n_stuffer reader_alert_out;
    struct s2n_stuffer writer_alert_out;

    /* Our handshake state machine */
    struct s2n_handshake handshake;

    /* Maximum outgoing fragment size for this connection. Does not limit
     * incoming record size.
     *
     * This value is updated when:
     *   1. s2n_connection_prefer_low_latency is set
     *   2. s2n_connection_prefer_throughput is set
     *   3. TLS Maximum Fragment Length extension is negotiated
     *
     * Default value: S2N_DEFAULT_FRAGMENT_LENGTH
     */
    uint16_t max_outgoing_fragment_length;

    /* The number of bytes to send before changing the record size. 
     * If this value > 0 then dynamic TLS record size is enabled. Otherwise, the feature is disabled (default). 
     */
    uint32_t dynamic_record_resize_threshold;

    /* Reset record size back to a single segment after threshold seconds of inactivity */
    uint16_t dynamic_record_timeout_threshold;

    /* number of bytes consumed during application activity */
    uint64_t active_application_bytes_consumed;

    /* Negotiated TLS extension Maximum Fragment Length code */
    uint8_t mfl_code;

    /* Keep some accounting on each connection */
    uint64_t wire_bytes_in;
    uint64_t wire_bytes_out;

    /* Is the connection open or closed ? We use C's only
     * atomic type as both the reader and the writer threads
     * may declare a connection closed.
     *
     * A connection can be gracefully closed or hard-closed.
     * When gracefully closed the reader or the writer mark
     * the connection as closing, and then the writer will
     * send an alert message before closing the connection
     * and marking it as closed.
     *
     * A hard-close goes straight to closed with no alert
     * message being sent.
     */
    sig_atomic_t closing;
    sig_atomic_t closed;

    /* TLS extension data */
    char server_name[S2N_MAX_SERVER_NAME + 1];

    /* The application protocol decided upon during the client hello.
     * If ALPN is being used, then:
     * In server mode, this will be set by the time client_hello_cb is invoked.
     * In client mode, this will be set after is_handshake_complete(connection) is true.
     */
    char application_protocol[256];

    /* OCSP stapling response data */
    s2n_status_request_type status_type;
    struct s2n_blob status_response;

    /* Certificate Transparency response data */
    s2n_ct_support_level ct_level_requested;
    struct s2n_blob ct_response;

    struct s2n_client_hello client_hello;

    struct s2n_x509_validator x509_validator;

    /* After a connection is created this is the verification function that should always be used. At init time,
     * the config should be checked for a verify callback and each connection should default to that. However,
     * from the user's perspective, it's sometimes simpler to manage state by attaching each validation function/data
     * to the connection, instead of globally to a single config.*/
    s2n_verify_host_fn verify_host_fn;
    void *data_for_verify_host;
    uint8_t verify_host_fn_overridden;

    /* Session ticket data */
    s2n_session_ticket_status session_ticket_status;
    struct s2n_blob client_ticket;
    uint32_t ticket_lifetime_hint;

    /* Session ticket extension from client to attempt to decrypt as the server. */
    uint8_t ticket_ext_data[S2N_TICKET_SIZE_IN_BYTES];
    struct s2n_stuffer client_ticket_to_decrypt;

    /* application protocols overridden */
    struct s2n_blob application_protocols_overridden;

    /* Cookie extension data */
    struct s2n_stuffer cookie_stuffer;
};

int s2n_connection_is_managed_corked(const struct s2n_connection *s2n_connection);
int s2n_connection_is_client_auth_enabled(struct s2n_connection *s2n_connection);

/* Kill a bad connection */
int s2n_connection_kill(struct s2n_connection *conn);

/* Send/recv a stuffer to/from a connection */
int s2n_connection_send_stuffer(struct s2n_stuffer *stuffer, struct s2n_connection *conn, uint32_t len);
int s2n_connection_recv_stuffer(struct s2n_stuffer *stuffer, struct s2n_connection *conn, uint32_t len);

extern int s2n_connection_get_cipher_preferences(struct s2n_connection *conn, const struct s2n_cipher_preferences **cipher_preferences);
extern int s2n_connection_get_protocol_preferences(struct s2n_connection *conn, struct s2n_blob **protocol_preferences);
extern int s2n_connection_set_client_auth_type(struct s2n_connection *conn, s2n_cert_auth_type cert_auth_type);
extern int s2n_connection_get_client_auth_type(struct s2n_connection *conn, s2n_cert_auth_type *client_cert_auth_type);
extern int s2n_connection_get_client_cert_chain(struct s2n_connection *conn, uint8_t **der_cert_chain_out, uint32_t *cert_chain_len);
