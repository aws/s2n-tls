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

#include <sys/param.h>

#include <s2n.h>
#include <time.h>

#include "error/s2n_errno.h"

#include "tls/s2n_connection.h"
#include "tls/s2n_alerts.h"
#include "tls/s2n_tls.h"
#include "tls/s2n_resume.h"
#include "tls/s2n_tls13_handshake.h"

#include "stuffer/s2n_stuffer.h"

#include "utils/s2n_safety.h"
#include "utils/s2n_random.h"

int s2n_server_nst_recv(struct s2n_connection *conn) {
    GUARD(s2n_stuffer_read_uint32(&conn->handshake.io, &conn->ticket_lifetime_hint));

    uint16_t session_ticket_len;
    GUARD(s2n_stuffer_read_uint16(&conn->handshake.io, &session_ticket_len));

    if (session_ticket_len > 0) {
        GUARD(s2n_realloc(&conn->client_ticket, session_ticket_len));

        GUARD(s2n_stuffer_read(&conn->handshake.io, &conn->client_ticket));
    }

    return 0;
}

int s2n_server_nst_send(struct s2n_connection *conn)
{
    uint16_t session_ticket_len = S2N_TICKET_SIZE_IN_BYTES;
    uint8_t data[S2N_TICKET_SIZE_IN_BYTES];
    struct s2n_blob entry = { .data = data, .size = sizeof(data) };
    struct s2n_stuffer to;
    uint32_t lifetime_hint_in_secs = (conn->config->encrypt_decrypt_key_lifetime_in_nanos + conn->config->decrypt_key_lifetime_in_nanos) / ONE_SEC_IN_NANOS;

    /* When server changes it's mind mid handshake send lifetime hint and session ticket length as zero */
    if (!conn->config->use_tickets) {
        GUARD(s2n_stuffer_write_uint32(&conn->handshake.io, 0));
        GUARD(s2n_stuffer_write_uint16(&conn->handshake.io, 0));

        return 0;
    }

    if (!s2n_server_sending_nst(conn)) {
        S2N_ERROR(S2N_ERR_SENDING_NST);
    }

    GUARD(s2n_stuffer_init(&to, &entry));
    GUARD(s2n_stuffer_write_uint32(&conn->handshake.io, lifetime_hint_in_secs));
    GUARD(s2n_stuffer_write_uint16(&conn->handshake.io, session_ticket_len));

    GUARD(s2n_encrypt_session_ticket(conn, NULL, &to));
    GUARD(s2n_stuffer_write(&conn->handshake.io, &to.blob));

    return 0;
}

int s2n_tls13_server_nst_send(struct s2n_connection *conn)
{
    notnull_check(conn);

    /* Write message type because session resumption in TLS13 is a post-handshake message */
    GUARD(s2n_stuffer_write_uint8(&conn->handshake.io, TLS_SERVER_NEW_SESSION_TICKET));

    struct s2n_stuffer_reservation message_size = { 0 };
    GUARD(s2n_stuffer_reserve_uint24(&conn->handshake.io, &message_size));

    /* Ticket lifetime is the minimum between key lifetime, session state lifetime, and one week */
    uint32_t key_lifetime_in_secs = (conn->config->encrypt_decrypt_key_lifetime_in_nanos +
            conn->config->decrypt_key_lifetime_in_nanos) / ONE_SEC_IN_NANOS;
    uint32_t session_state_lifetime_in_secs = conn->config->session_state_lifetime_in_nanos / ONE_SEC_IN_NANOS;

    uint32_t minimum_key_and_session_lifetime = MIN(key_lifetime_in_secs, session_state_lifetime_in_secs);
    uint32_t ticket_lifetime = MIN(minimum_key_and_session_lifetime, ONE_WEEK_IN_SECS);

    GUARD(s2n_stuffer_write_uint32(&conn->handshake.io, ticket_lifetime));

    /* Get random data to use as ticket_age_add value */
    struct s2n_ticket_fields ticket_fields = { 0 };
    struct s2n_blob random_data = { 0 };
    GUARD(s2n_blob_init(&random_data, ticket_fields.ticket_age_add, sizeof(ticket_fields.ticket_age_add)));
    GUARD_AS_POSIX(s2n_get_private_random_data(&random_data));
    GUARD(s2n_stuffer_write_bytes(&conn->handshake.io, random_data.data, sizeof(ticket_fields.ticket_age_add)));

    /* Write ticket nonce */
    GUARD(s2n_stuffer_write_uint8(&conn->handshake.io, sizeof(conn->tickets_sent)));
    GUARD(s2n_stuffer_write_uint16(&conn->handshake.io, conn->tickets_sent));

    /* Derive individual session ticket secret */
    s2n_tls13_connection_keys(secrets, conn);
    s2n_stack_blob(ticket_secret, secrets.size, S2N_TLS13_SECRET_MAX_LEN);

    uint8_t blob_data[sizeof(uint16_t)] = { 0 };
    struct s2n_blob nonce_blob = { 0 };
    struct s2n_stuffer ticket_nonce = { 0 };
    GUARD(s2n_blob_init(&nonce_blob, blob_data, sizeof(conn->tickets_sent)));
    GUARD(s2n_stuffer_init(&ticket_nonce, &nonce_blob));
    GUARD(s2n_stuffer_write_uint16(&ticket_nonce, conn->tickets_sent));

    struct s2n_blob master_secret = { 0 };
    GUARD(s2n_blob_init(&master_secret, conn->resumption_master_secret, sizeof(conn->resumption_master_secret)));
    GUARD_AS_POSIX(s2n_tls13_derive_session_ticket_secret(&secrets, &master_secret, &ticket_nonce.blob, &ticket_secret));

    ticket_fields.session_secret = ticket_secret;

    /* Create ticket */
    uint8_t ticket_data[S2N_MAX_TICKET_SIZE_IN_BYTES] = { 0 };
    struct s2n_blob ticket_blob = { 0 };
    struct s2n_stuffer session_ticket = { 0 };
    GUARD(s2n_blob_init(&ticket_blob, ticket_data, sizeof(ticket_data)));
    GUARD(s2n_stuffer_init(&session_ticket, &ticket_blob));

    GUARD(s2n_encrypt_session_ticket(conn, &ticket_fields, &session_ticket));

    /* Write session ticket length */
    GUARD(s2n_stuffer_write_uint8(&conn->handshake.io, s2n_stuffer_data_available(&session_ticket)));

    GUARD(s2n_stuffer_write(&conn->handshake.io, &session_ticket.blob));

    /* Write size of new session ticket extensions */
    GUARD(s2n_stuffer_write_uint16(&conn->handshake.io, 0));

    GUARD(s2n_stuffer_write_vector_size(&message_size));

    conn->tickets_sent++;

    return S2N_SUCCESS;
}
