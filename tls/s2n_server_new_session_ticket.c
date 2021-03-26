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
#include "tls/s2n_record.h"

#include "stuffer/s2n_stuffer.h"

#include "utils/s2n_safety.h"
#include "utils/s2n_random.h"

#define TLS13_MAX_NEW_SESSION_TICKET_SIZE sizeof(uint8_t)  + /* message type   */ \
                                          SIZEOF_UINT24    + /* message length */ \
                                          sizeof(uint32_t) + /* ticket lifetime */ \
                                          sizeof(uint32_t) + /* ticket age add */ \
                                          sizeof(uint8_t)  + /* nonce length */ \
                                          sizeof(uint16_t) + /* nonce */ \
                                          sizeof(uint16_t) + /* ticket length */ \
                                          S2N_MAX_TICKET_SIZE_IN_BYTES + /* ticket */ \
                                          sizeof(uint16_t)   /* extensions length */

int s2n_server_nst_recv(struct s2n_connection *conn) {
    POSIX_GUARD(s2n_stuffer_read_uint32(&conn->handshake.io, &conn->ticket_lifetime_hint));

    uint16_t session_ticket_len;
    POSIX_GUARD(s2n_stuffer_read_uint16(&conn->handshake.io, &session_ticket_len));

    if (session_ticket_len > 0) {
        POSIX_GUARD(s2n_realloc(&conn->client_ticket, session_ticket_len));

        POSIX_GUARD(s2n_stuffer_read(&conn->handshake.io, &conn->client_ticket));

        if (conn->config->session_ticket_cb != NULL) {
            size_t session_len = s2n_connection_get_session_length(conn);
            POSIX_ENSURE_GTE(S2N_TLS12_SESSION_SIZE, session_len);

            /* Alloc some memory for the serialized session ticket */
            DEFER_CLEANUP(struct s2n_blob mem = { 0 }, s2n_free);
            POSIX_GUARD(s2n_alloc(&mem, S2N_STATE_FORMAT_LEN + S2N_SESSION_TICKET_SIZE_LEN + \
                    conn->client_ticket.size + S2N_STATE_SIZE_IN_BYTES));

            POSIX_GUARD(s2n_connection_get_session(conn, mem.data, session_len));
            uint32_t session_lifetime = s2n_connection_get_session_ticket_lifetime_hint(conn);

            struct s2n_session_ticket ticket = { .ticket_data = mem, .session_lifetime = session_lifetime };

            POSIX_GUARD(conn->config->session_ticket_cb(conn, &ticket));
        }
    }

    return 0;
}

int s2n_server_nst_send(struct s2n_connection *conn)
{
    uint16_t session_ticket_len = S2N_TLS12_TICKET_SIZE_IN_BYTES;
    uint8_t data[S2N_TLS12_TICKET_SIZE_IN_BYTES] = { 0 };
    struct s2n_blob entry = { .data = data, .size = sizeof(data) };
    struct s2n_stuffer to;
    uint32_t lifetime_hint_in_secs = (conn->config->encrypt_decrypt_key_lifetime_in_nanos + conn->config->decrypt_key_lifetime_in_nanos) / ONE_SEC_IN_NANOS;

    /* When server changes it's mind mid handshake send lifetime hint and session ticket length as zero */
    if (!conn->config->use_tickets) {
        POSIX_GUARD(s2n_stuffer_write_uint32(&conn->handshake.io, 0));
        POSIX_GUARD(s2n_stuffer_write_uint16(&conn->handshake.io, 0));

        return 0;
    }

    if (!s2n_server_sending_nst(conn)) {
        POSIX_BAIL(S2N_ERR_SENDING_NST);
    }

    POSIX_GUARD(s2n_stuffer_init(&to, &entry));
    POSIX_GUARD(s2n_stuffer_write_uint32(&conn->handshake.io, lifetime_hint_in_secs));
    POSIX_GUARD(s2n_stuffer_write_uint16(&conn->handshake.io, session_ticket_len));

    POSIX_GUARD(s2n_encrypt_session_ticket(conn, NULL, &to));
    POSIX_GUARD(s2n_stuffer_write(&conn->handshake.io, &to.blob));

    return 0;
}

S2N_RESULT s2n_tls13_server_nst_send(struct s2n_connection *conn, s2n_blocked_status *blocked)
{
    RESULT_ENSURE_REF(conn);

    if (conn->mode != S2N_SERVER || conn->actual_protocol_version < S2N_TLS13) {
        return S2N_RESULT_OK;
    }

    RESULT_ENSURE(conn->tickets_sent <= conn->tickets_to_send, S2N_ERR_INTEGER_OVERFLOW);
    while (conn->tickets_to_send - conn->tickets_sent > 0) {
        uint8_t nst_data[TLS13_MAX_NEW_SESSION_TICKET_SIZE] = { 0 };
        struct s2n_blob nst_blob = { 0 };
        struct s2n_stuffer nst_stuffer = { 0 };
        RESULT_GUARD_POSIX(s2n_blob_init(&nst_blob, nst_data, sizeof(nst_data)));
        RESULT_GUARD_POSIX(s2n_stuffer_init(&nst_stuffer, &nst_blob));

        RESULT_GUARD(s2n_tls13_server_nst_write(conn, &nst_stuffer));
        nst_blob.size = s2n_stuffer_data_available(&nst_stuffer);

        RESULT_GUARD_POSIX(s2n_record_write(conn, TLS_HANDSHAKE, &nst_blob));
        RESULT_GUARD_POSIX(s2n_flush(conn, blocked));
    }

    return S2N_RESULT_OK;
}

/** 
 *= https://tools.ietf.org/rfc/rfc8446#section-4.6.1
 *# Indicates the lifetime in seconds as a 32-bit
 *# unsigned integer in network byte order from the time of ticket
 *# issuance. 
 **/
static S2N_RESULT s2n_generate_ticket_lifetime(struct s2n_connection *conn, uint32_t *ticket_lifetime) 
{
    RESULT_ENSURE_REF(conn);
    RESULT_ENSURE_MUT(ticket_lifetime);

    uint32_t key_lifetime_in_secs = conn->config->decrypt_key_lifetime_in_nanos / ONE_SEC_IN_NANOS;
    uint32_t session_lifetime_in_secs = conn->config->session_state_lifetime_in_nanos / ONE_SEC_IN_NANOS;
    uint32_t key_and_session_min_lifetime = MIN(key_lifetime_in_secs, session_lifetime_in_secs);
    /** 
     *= https://tools.ietf.org/rfc/rfc8446#section-4.6.1
     *# Servers MUST NOT use any value greater than
     *# 604800 seconds (7 days).
     **/
    *ticket_lifetime = MIN(key_and_session_min_lifetime, ONE_WEEK_IN_SEC);

    return S2N_RESULT_OK;
}

/** 
 *= https://tools.ietf.org/rfc/rfc8446#section-4.6.1
 *# A per-ticket value that is unique across all tickets
 *# issued on this connection.
 **/
static S2N_RESULT s2n_generate_ticket_nonce(uint16_t value, struct s2n_blob *output)
{
    RESULT_ENSURE_MUT(output);

    struct s2n_stuffer stuffer = { 0 };
    RESULT_GUARD_POSIX(s2n_stuffer_init(&stuffer, output));
    RESULT_GUARD_POSIX(s2n_stuffer_write_uint16(&stuffer, value));

    return S2N_RESULT_OK;
}

/** 
 *= https://tools.ietf.org/rfc/rfc8446#section-4.6.1
 *# A securely generated, random 32-bit value that is
 *# used to obscure the age of the ticket that the client includes in
 *# the "pre_shared_key" extension.
 **/
static S2N_RESULT s2n_generate_ticket_age_add(struct s2n_blob *random_data, uint32_t *ticket_age_add)
{
    RESULT_ENSURE_REF(random_data);
    RESULT_ENSURE_REF(ticket_age_add);

    struct s2n_stuffer stuffer = { 0 };
    RESULT_GUARD_POSIX(s2n_stuffer_init(&stuffer, random_data));
    RESULT_GUARD_POSIX(s2n_stuffer_skip_write(&stuffer, random_data->size));
    RESULT_GUARD_POSIX(s2n_stuffer_read_uint32(&stuffer, ticket_age_add));

    return S2N_RESULT_OK;
}

/**
 *= https://tools.ietf.org/rfc/rfc8446#section-4.6.1
 *# The PSK associated with the ticket is computed as:
 *#
 *#    HKDF-Expand-Label(resumption_master_secret,
 *#                     "resumption", ticket_nonce, Hash.length)
 **/
static int s2n_generate_session_secret(struct s2n_connection *conn, struct s2n_blob *nonce, uint8_t *secret_mem, struct s2n_blob *output)
{
    POSIX_ENSURE_REF(conn);
    POSIX_ENSURE_REF(nonce);
    POSIX_ENSURE_REF(secret_mem);
    POSIX_ENSURE_REF(output);

    s2n_tls13_connection_keys(secrets, conn);
    struct s2n_blob master_secret = { 0 };
    POSIX_GUARD(s2n_blob_init(&master_secret, conn->resumption_master_secret, secrets.size));
    POSIX_GUARD(s2n_blob_init(output, secret_mem, secrets.size));
    POSIX_GUARD_RESULT(s2n_tls13_derive_session_ticket_secret(&secrets, &master_secret, nonce, output));

    return S2N_SUCCESS;
}

S2N_RESULT s2n_tls13_server_nst_write(struct s2n_connection *conn, struct s2n_stuffer *output)
{
    RESULT_ENSURE_REF(conn);
    RESULT_ENSURE_REF(output);

    /* Write message type because session resumption in TLS13 is a post-handshake message */
    RESULT_GUARD_POSIX(s2n_stuffer_write_uint8(output, TLS_SERVER_NEW_SESSION_TICKET));

    struct s2n_stuffer_reservation message_size = { 0 };
    RESULT_GUARD_POSIX(s2n_stuffer_reserve_uint24(output, &message_size));

    uint32_t ticket_lifetime_in_secs = 0;
    RESULT_GUARD(s2n_generate_ticket_lifetime(conn, &ticket_lifetime_in_secs));
    RESULT_GUARD_POSIX(s2n_stuffer_write_uint32(output, ticket_lifetime_in_secs));

    /* Get random data to use as ticket_age_add value */
    struct s2n_ticket_fields ticket_fields = { 0 };
    uint8_t data[sizeof(uint32_t)] = { 0 };
    struct s2n_blob random_data = { 0 };
    RESULT_GUARD_POSIX(s2n_blob_init(&random_data, data, sizeof(data)));
    /** 
     *= https://tools.ietf.org/rfc/rfc8446#section-4.6.1
     *#  The server MUST generate a fresh value
     *#  for each ticket it sends.
     **/
    RESULT_GUARD(s2n_get_private_random_data(&random_data));
    RESULT_GUARD(s2n_generate_ticket_age_add(&random_data, &ticket_fields.ticket_age_add));
    RESULT_GUARD_POSIX(s2n_stuffer_write_uint32(output, ticket_fields.ticket_age_add));

    /* Write ticket nonce */
    uint8_t nonce_data[sizeof(uint16_t)] = { 0 };
    struct s2n_blob nonce = { 0 };
    RESULT_GUARD_POSIX(s2n_blob_init(&nonce, nonce_data, sizeof(nonce_data)));
    RESULT_GUARD(s2n_generate_ticket_nonce(conn->tickets_sent, &nonce));
    RESULT_GUARD_POSIX(s2n_stuffer_write_uint8(output, nonce.size));
    RESULT_GUARD_POSIX(s2n_stuffer_write_bytes(output, nonce.data, nonce.size));

    /* Derive individual session ticket secret */
    uint8_t session_secret_data[S2N_TLS13_SECRET_MAX_LEN] = { 0 };
    RESULT_GUARD_POSIX(s2n_generate_session_secret(conn, &nonce, session_secret_data, &ticket_fields.session_secret));

    /* Create ticket */
    uint8_t ticket_data[S2N_MAX_TICKET_SIZE_IN_BYTES] = { 0 };
    struct s2n_blob ticket_blob = { 0 };
    struct s2n_stuffer session_ticket = { 0 };
    RESULT_GUARD_POSIX(s2n_blob_init(&ticket_blob, ticket_data, sizeof(ticket_data)));
    RESULT_GUARD_POSIX(s2n_stuffer_init(&session_ticket, &ticket_blob));
    RESULT_GUARD_POSIX(s2n_encrypt_session_ticket(conn, &ticket_fields, &session_ticket));
    /* The encrypted ticket may be less than S2N_MAX_TICKET_SIZE_IN_BYTES */
    ticket_blob.size = s2n_stuffer_data_available(&session_ticket);

    /* Write session ticket */
    RESULT_ENSURE(ticket_blob.size <= UINT8_MAX, S2N_ERR_SAFETY);
    RESULT_GUARD_POSIX(s2n_stuffer_write_uint16(output, ticket_blob.size));
    RESULT_GUARD_POSIX(s2n_stuffer_write(output, &ticket_blob));

    RESULT_GUARD_POSIX(s2n_extension_list_send(S2N_EXTENSION_LIST_NST, conn, output));

    RESULT_GUARD_POSIX(s2n_stuffer_write_vector_size(&message_size));

    RESULT_ENSURE(conn->tickets_sent < UINT16_MAX, S2N_ERR_INTEGER_OVERFLOW);
    conn->tickets_sent++;

    return S2N_RESULT_OK;
}

/**
 *= https://tools.ietf.org/rfc/rfc8446#section-4.6.1
 *#     struct {
 *#         uint32 ticket_lifetime;
 *#         uint32 ticket_age_add;
 *#         opaque ticket_nonce<0..255>;
 *#         opaque ticket<1..2^16-1>;
 *#         Extension extensions<0..2^16-2>;
 *#      } NewSessionTicket;
**/
S2N_RESULT s2n_tls13_server_nst_recv(struct s2n_connection *conn, struct s2n_stuffer *input)
{
    RESULT_ENSURE_REF(conn);
    RESULT_ENSURE_REF(input);

    RESULT_ENSURE(conn->mode == S2N_CLIENT, S2N_ERR_BAD_MESSAGE);

    if (conn->config->session_ticket_cb != NULL) {
        uint32_t ticket_lifetime = 0;
        RESULT_GUARD_POSIX(s2n_stuffer_read_uint32(input, &ticket_lifetime));
        /**
         *= https://tools.ietf.org/rfc/rfc8446#section-4.6.1
         *# The value of zero indicates that the
         *# ticket should be discarded immediately.
         */
        if (ticket_lifetime == 0) {
            return S2N_RESULT_OK;
        }
        struct s2n_ticket_fields ticket_fields = { 0 };
        RESULT_GUARD_POSIX(s2n_stuffer_read_uint32(input, &ticket_fields.ticket_age_add));

        uint8_t ticket_nonce_len = 0;
        RESULT_GUARD_POSIX(s2n_stuffer_read_uint8(input, &ticket_nonce_len));
        uint8_t nonce_data[UINT8_MAX] = { 0 };
        struct s2n_blob nonce = { 0 };
        RESULT_GUARD_POSIX(s2n_blob_init(&nonce, nonce_data, ticket_nonce_len));
        RESULT_GUARD_POSIX(s2n_stuffer_read_bytes(input, nonce.data, ticket_nonce_len));

        uint16_t session_ticket_len = 0;
        RESULT_GUARD_POSIX(s2n_stuffer_read_uint16(input, &session_ticket_len));
        RESULT_ENSURE(session_ticket_len > 0, S2N_ERR_SAFETY);
        RESULT_GUARD_POSIX(s2n_realloc(&conn->client_ticket, session_ticket_len));
        RESULT_GUARD_POSIX(s2n_stuffer_read(input, &conn->client_ticket));

        RESULT_GUARD_POSIX(s2n_extension_list_recv(S2N_EXTENSION_LIST_NST, conn, input));

        /* Derive individual session ticket secret */
        uint8_t session_secret_data[S2N_TLS13_SECRET_MAX_LEN] = { 0 };
        RESULT_GUARD_POSIX(s2n_generate_session_secret(conn, &nonce, session_secret_data, &ticket_fields.session_secret));

        /* Alloc some memory for the serialized session ticket */
        DEFER_CLEANUP(struct s2n_blob mem = { 0 }, s2n_free);
        RESULT_GUARD_POSIX(s2n_alloc(&mem, S2N_STATE_FORMAT_LEN + S2N_SESSION_TICKET_SIZE_LEN + \
                conn->client_ticket.size + S2N_MAX_STATE_SIZE_IN_BYTES));

        struct s2n_stuffer session_stuffer = { 0 };
        RESULT_GUARD_POSIX(s2n_stuffer_init(&session_stuffer, &mem));

        /* Serialize resumption state */
        RESULT_GUARD_POSIX(s2n_client_serialize_resumption_state(conn, &ticket_fields, &session_stuffer));
        session_stuffer.blob.size = s2n_stuffer_data_available(&session_stuffer);
        struct s2n_session_ticket ticket = { .ticket_data = session_stuffer.blob, .session_lifetime = ticket_lifetime };

        RESULT_GUARD_POSIX(conn->config->session_ticket_cb(conn, &ticket));
    }

    return S2N_RESULT_OK;
}
