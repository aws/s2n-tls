/*
 * Copyright 2014 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

#include <errno.h>
#include <s2n.h>

#include "tls/s2n_connection.h"
#include "tls/s2n_record.h"
#include "tls/s2n_alerts.h"
#include "tls/s2n_tls.h"

#include "stuffer/s2n_stuffer.h"

#include "utils/s2n_safety.h"

/* From RFC5246 7.4 */
#define TLS_HELLO_REQUEST       0
#define TLS_CLIENT_HELLO        1
#define TLS_SERVER_HELLO        2
#define TLS_SERVER_CERT         11
#define TLS_SERVER_KEY          12
#define TLS_SERVER_CERT_REQ     13
#define TLS_SERVER_HELLO_DONE   14
#define TLS_CLIENT_CERT         11  /* Same as SERVER_CERT */
#define TLS_CLIENT_CERT_VERIFY  15
#define TLS_CLIENT_KEY          16
#define TLS_CLIENT_FINISHED     20
#define TLS_SERVER_FINISHED     20  /* Same as CLIENT_FINISHED */

struct s2n_handshake_action {
    uint8_t record_type;
    uint8_t message_type;
    char writer;                /* 'S' or 'C' for server or client, 'B' for both */
    int (*handler[2]) (struct s2n_connection * conn, const char **err);
};

static struct s2n_handshake_action state_machine[] = {
    /*Message type  Handshake type         Writer       S2N_SERVER                S2N_CLIENT                   handshake.state           */
    {TLS_HANDSHAKE, TLS_CLIENT_HELLO, 'C', {s2n_client_hello_recv, s2n_client_hello_send}}, /* CLIENT_HELLO              */
    {TLS_HANDSHAKE, TLS_SERVER_HELLO, 'S', {s2n_server_hello_send, s2n_server_hello_recv}}, /* SERVER_HELLO              */
    {TLS_HANDSHAKE, TLS_SERVER_CERT, 'S', {s2n_server_cert_send, s2n_server_cert_recv}},    /* SERVER_CERT               */
    {TLS_HANDSHAKE, TLS_SERVER_KEY, 'S', {s2n_server_key_send, s2n_server_key_recv}},   /* SERVER_KEY                */
    {TLS_HANDSHAKE, TLS_SERVER_CERT_REQ, 'S', {NULL, NULL}},    /* SERVER_CERT_REQ           */
    {TLS_HANDSHAKE, TLS_SERVER_HELLO_DONE, 'S', {s2n_server_done_send, s2n_server_done_recv}},  /* SERVER_HELLO_DONE         */
    {TLS_HANDSHAKE, TLS_CLIENT_CERT, 'C', {NULL, NULL}},    /* CLIENT_CERT               */
    {TLS_HANDSHAKE, TLS_CLIENT_KEY, 'C', {s2n_client_key_recv, s2n_client_key_send}},   /* CLIENT_KEY                */
    {TLS_HANDSHAKE, TLS_CLIENT_CERT_VERIFY, 'C', {NULL, NULL}}, /* CLIENT_CERT_VERIFY        */
    {TLS_CHANGE_CIPHER_SPEC, 0, 'C', {s2n_client_ccs_recv, s2n_client_ccs_send}},   /* CLIENT_CHANGE_CIPHER_SPEC */
    {TLS_HANDSHAKE, TLS_CLIENT_FINISHED, 'C', {s2n_client_finished_recv, s2n_client_finished_send}},    /* CLIENT_FINISHED           */
    {TLS_CHANGE_CIPHER_SPEC, 0, 'S', {s2n_server_ccs_send, s2n_server_ccs_recv}},   /* SERVER_CHANGE_CIPHER_SPEC */
    {TLS_HANDSHAKE, TLS_SERVER_FINISHED, 'S', {s2n_server_finished_send, s2n_server_finished_recv}},    /* SERVER_FINISHED           */
    {TLS_APPLICATION_DATA, 0, 'B', {NULL, NULL}}    /* HANDSHAKE_OVER            */
};

static int s2n_conn_update_handshake_hashes(struct s2n_connection *conn, struct s2n_blob *data, const char **err)
{
    GUARD(s2n_hash_update(&conn->handshake.client_md5, data->data, data->size, err));
    GUARD(s2n_hash_update(&conn->handshake.client_sha1, data->data, data->size, err));
    GUARD(s2n_hash_update(&conn->handshake.client_sha256, data->data, data->size, err));
    GUARD(s2n_hash_update(&conn->handshake.server_md5, data->data, data->size, err));
    GUARD(s2n_hash_update(&conn->handshake.server_sha1, data->data, data->size, err));
    GUARD(s2n_hash_update(&conn->handshake.server_sha256, data->data, data->size, err));

    return 0;
}

/* Writing is relatively straight forward, simply write each message out as a record,
 * we may fragment a message across multiple records, but we never coalesce multiple
 * messages into single records. 
 */
static int handshake_write_io(struct s2n_connection *conn, const char **err)
{
    uint8_t record_type = state_machine[conn->handshake.state].record_type;
    int more = 0;
    int max_payload_size;

    /* If there's nothing in the out stuffer, put a handshake message in the 
     * handshake stuffer.
     */
    if (s2n_stuffer_data_available(&conn->out) == 0) {
        if (record_type == TLS_HANDSHAKE) {
            GUARD(s2n_handshake_write_header(conn, state_machine[conn->handshake.state].message_type, err));
        }
        GUARD(state_machine[conn->handshake.state].handler[conn->mode] (conn, err));
        if (record_type == TLS_HANDSHAKE) {
            GUARD(s2n_handshake_finish_header(conn, err));
        }
    }

    /* Write the handshake data to records  */
    struct s2n_blob out;
    out.size = s2n_stuffer_data_available(&conn->handshake.io);

    /* ... in fragment sized chunks */
    GUARD((max_payload_size = s2n_record_max_write_payload_size(conn, err)));
    if (out.size > max_payload_size) {
        out.size = max_payload_size;
    }
    out.data = s2n_stuffer_raw_read(&conn->handshake.io, out.size, err);
    notnull_check(out.data);

    /* Make the actual record */
    GUARD(s2n_record_write(conn, record_type, &out, err));

    /* MD5 and SHA sum the handshake data too */
    if (record_type == TLS_HANDSHAKE) {
        GUARD(s2n_conn_update_handshake_hashes(conn, &out, err));
    }

    /* Actually send the record */
    GUARD(s2n_flush(conn, &more, err));

    /* If we're done sending the last record, reset everything */
    if (s2n_stuffer_data_available(&conn->handshake.io) == 0) {
        GUARD(s2n_stuffer_wipe(&conn->out, err));
        GUARD(s2n_stuffer_wipe(&conn->handshake.io, err));

        /* Advance the state machine */
        conn->handshake.state = conn->handshake.next_state;
    }

    return 0;
}

/*
 * Returns:
 *  1  - more data is needed to complete the handshake message.
 *  0  - we read the whole handshake message.
 * -1  - error processing the handshake message.
 */
static int read_full_handshake_message(struct s2n_connection *conn, uint8_t *message_type, const char **err)
{
    uint32_t current_handshake_data = s2n_stuffer_data_available(&conn->handshake.io);
    if (current_handshake_data < TLS_HANDSHAKE_HEADER_LENGTH) {
        /* The message may be so badly fragmented that we don't even read the full header, take
         * what we can and then continue to the next record read iteration. 
         */
        if (s2n_stuffer_data_available(&conn->in) < (TLS_HANDSHAKE_HEADER_LENGTH - current_handshake_data)) {
            GUARD(s2n_stuffer_copy(&conn->in, &conn->handshake.io, s2n_stuffer_data_available(&conn->in), err));
            return 1;
        }

        /* Get the remainder of the header */
        GUARD(s2n_stuffer_copy(&conn->in, &conn->handshake.io, (TLS_HANDSHAKE_HEADER_LENGTH - current_handshake_data), err));
    }

    uint32_t handshake_message_length;
    GUARD(s2n_handshake_parse_header(conn, message_type, &handshake_message_length, err));

    if (handshake_message_length > S2N_MAXIMUM_HANDSHAKE_MESSAGE_LENGTH) {
        *err = "Handshake message is too long";
        return -1;
    }

    uint32_t bytes_to_take = handshake_message_length - s2n_stuffer_data_available(&conn->handshake.io);;
    if (bytes_to_take > s2n_stuffer_data_available(&conn->in)) {
        bytes_to_take = s2n_stuffer_data_available(&conn->in);
    }

    /* If the record is handshake data, add it to the handshake buffer */
    GUARD(s2n_stuffer_copy(&conn->in, &conn->handshake.io, bytes_to_take, err));

    /* If we have the whole handshake message, then success */
    if (s2n_stuffer_data_available(&conn->handshake.io) == handshake_message_length) {
        struct s2n_blob handshake;
        handshake.data = conn->handshake.io.blob.data;
        handshake.size = TLS_HANDSHAKE_HEADER_LENGTH + handshake_message_length;

        notnull_check(handshake.data);

        /* MD5 and SHA sum the handshake data too */
        GUARD(s2n_conn_update_handshake_hashes(conn, &handshake, err));

        return 0;
    }

    /* We don't have the whole message, so we'll need to go again */
    GUARD(s2n_stuffer_reread(&conn->handshake.io, err));

    return 1;
}

/* Reading is a little more complicated than writing as the TLS RFCs allow content
 * types to be interleaved at the record layer. We may get an alert message
 * during the handshake phase, or messages of types that we don't support (e.g.
 * HEARTBEAT messages), or during renegotiations we may even get application
 * data messages that need to be handled by the application. The latter is punted
 * for now (s2n does support renegotiations).
 */
static int handshake_read_io(struct s2n_connection *conn, const char **err)
{
    uint8_t record_type;
    int isSSLv2;

    int r = s2n_read_full_record(conn, &record_type, &isSSLv2, err);
    if (r < 0) {
        if (r == -2) {
            conn->closed = 1;
        }
        return -1;
    }

    if (isSSLv2) {
        if (conn->handshake.state != CLIENT_HELLO) {
            *err = "Received SSLv2 record";
            return -1;
        }

        /* Add the message to our handshake hashes */
        struct s2n_blob hashed = {.data = conn->header_in.blob.data + 2,.size = 3 };
        GUARD(s2n_conn_update_handshake_hashes(conn, &hashed, err));

        hashed.data = conn->in.blob.data;
        hashed.size = s2n_stuffer_data_available(&conn->in);
        GUARD(s2n_conn_update_handshake_hashes(conn, &hashed, err));

        /* Handle an SSLv2 client hello */
        GUARD(s2n_stuffer_copy(&conn->in, &conn->handshake.io, s2n_stuffer_data_available(&conn->in), err));
        GUARD(s2n_sslv2_client_hello_recv(conn, err));
        GUARD(s2n_stuffer_wipe(&conn->handshake.io, err));

        /* We're done with the record, wipe it */
        GUARD(s2n_stuffer_wipe(&conn->header_in, err));
        GUARD(s2n_stuffer_wipe(&conn->in, err));
        conn->in_status = ENCRYPTED;

        /* Advance the state machine */
        conn->handshake.state = conn->handshake.next_state;
    }

    /* Now we have a record, but it could be a partial fragment of a message, or it might
     * contain several messages.
     */
    if (record_type == TLS_APPLICATION_DATA) {
        *err = "Received application data before the handshake concluded";
        return -1;
    } else if (record_type == TLS_CHANGE_CIPHER_SPEC) {
        if (s2n_stuffer_data_available(&conn->in) != 1) {
            *err = "Received invalid change cipher spec message";
            return -1;
        }

        GUARD(s2n_stuffer_copy(&conn->in, &conn->handshake.io, s2n_stuffer_data_available(&conn->in), err));
        GUARD(state_machine[conn->handshake.state].handler[conn->mode] (conn, err));
        GUARD(s2n_stuffer_wipe(&conn->handshake.io, err));

        /* We're done with the record, wipe it */
        GUARD(s2n_stuffer_wipe(&conn->header_in, err));
        GUARD(s2n_stuffer_wipe(&conn->in, err));
        conn->in_status = ENCRYPTED;

        /* Advance the state machine */
        conn->handshake.state = conn->handshake.next_state;

        return 0;
    } else if (record_type != TLS_HANDSHAKE) {
        if (record_type == TLS_ALERT) {
            GUARD(s2n_process_alert_fragment(conn, err));
        }

        /* Ignore record types that we don't support */

        /* We're done with the record, wipe it */
        GUARD(s2n_stuffer_wipe(&conn->header_in, err));
        GUARD(s2n_stuffer_wipe(&conn->in, err));
        conn->in_status = ENCRYPTED;
        return 0;
    }

    /* Record is a handshake message */
    while (s2n_stuffer_data_available(&conn->in)) {
        uint8_t handshake_message_type;
        GUARD((r = read_full_handshake_message(conn, &handshake_message_type, err)));

        /* Do we need more data? */
        if (r == 1) {
            /* Break out of this inner loop, but since we're not changing the state, the
             * outer loop in s2n_handshake_io() will read another record. 
             */
            GUARD(s2n_stuffer_wipe(&conn->header_in, err));
            GUARD(s2n_stuffer_wipe(&conn->in, err));
            conn->in_status = ENCRYPTED;
            return 0;
        }

        if (handshake_message_type != state_machine[conn->handshake.state].message_type) {
            *err = "Received a handshake message out of order";
            return -1;
        }

        /* Call the relevant handler */
        GUARD(state_machine[conn->handshake.state].handler[conn->mode] (conn, err));
        GUARD(s2n_stuffer_wipe(&conn->handshake.io, err));

        /* Advance the state machine */
        conn->handshake.state = conn->handshake.next_state;
    }

    /* We're done with the record, wipe it */
    GUARD(s2n_stuffer_wipe(&conn->header_in, err));
    GUARD(s2n_stuffer_wipe(&conn->in, err));
    conn->in_status = ENCRYPTED;

    return 0;
}

int s2n_negotiate(struct s2n_connection *conn, int *more, const char **err)
{
    char this = 'S';
    if (conn->mode == S2N_CLIENT) {
        this = 'C';
    }

    while (state_machine[conn->handshake.state].writer != 'B') {

        /* Flush any pending I/O or alert messages */
        GUARD(s2n_flush(conn, more, err));
        *more = 1;

        if (state_machine[conn->handshake.state].writer == this) {
            GUARD(handshake_write_io(conn, err));
        } else {
            GUARD(handshake_read_io(conn, err));
        }

        /* If the handshake has just ended, free up memory */
        if (state_machine[conn->handshake.state].writer == 'B') {
            GUARD(s2n_stuffer_resize(&conn->handshake.io, 0, err));
        }
    }

    *more = 0;

    return 0;
}
