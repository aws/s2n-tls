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
    uint16_t session_ticket_len = S2N_TLS12_TICKET_SIZE_IN_BYTES;
    uint8_t data[S2N_TLS12_TICKET_SIZE_IN_BYTES] = { 0 };
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

/** 
 *= https://tools.ietf.org/rfc/rfc8446#section-4.6.1
 *# Indicates the lifetime in seconds as a 32-bit
 *# unsigned integer in network byte order from the time of ticket
 *# issuance. 
 **/
static S2N_RESULT s2n_generate_ticket_lifetime(struct s2n_connection *conn, uint32_t *ticket_lifetime) 
{
    ENSURE_REF(conn);
    ENSURE_MUT(ticket_lifetime);

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
    ENSURE_MUT(output);

    struct s2n_stuffer stuffer = { 0 };
    GUARD_AS_RESULT(s2n_stuffer_init(&stuffer, output));
    GUARD_AS_RESULT(s2n_stuffer_write_uint16(&stuffer, value));

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
    ENSURE_REF(random_data);
    ENSURE_REF(ticket_age_add);

    struct s2n_stuffer stuffer = { 0 };
    GUARD_AS_RESULT(s2n_stuffer_init(&stuffer, random_data));
    GUARD_AS_RESULT(s2n_stuffer_skip_write(&stuffer, random_data->size));
    GUARD_AS_RESULT(s2n_stuffer_read_uint32(&stuffer, ticket_age_add));

    return S2N_RESULT_OK;
}

int s2n_tls13_server_nst_send(struct s2n_connection *conn)
{
    notnull_check(conn);

    /* Write message type because session resumption in TLS13 is a post-handshake message */
    GUARD(s2n_stuffer_write_uint8(&conn->handshake.io, TLS_SERVER_NEW_SESSION_TICKET));

    struct s2n_stuffer_reservation message_size = { 0 };
    GUARD(s2n_stuffer_reserve_uint24(&conn->handshake.io, &message_size));

    uint32_t ticket_lifetime_in_secs = 0;
    GUARD_AS_POSIX(s2n_generate_ticket_lifetime(conn, &ticket_lifetime_in_secs));
    GUARD(s2n_stuffer_write_uint32(&conn->handshake.io, ticket_lifetime_in_secs));

    /* Get random data to use as ticket_age_add value */
    struct s2n_ticket_fields ticket_fields = { 0 };
    uint8_t data[sizeof(uint32_t)] = { 0 };
    struct s2n_blob random_data = { 0 };
    GUARD(s2n_blob_init(&random_data, data, sizeof(data)));
    /** 
     *= https://tools.ietf.org/rfc/rfc8446#section-4.6.1
     *#  The server MUST generate a fresh value
     *#  for each ticket it sends.
     **/
    GUARD_AS_POSIX(s2n_get_private_random_data(&random_data));
    GUARD_AS_POSIX(s2n_generate_ticket_age_add(&random_data, &ticket_fields.ticket_age_add));
    GUARD(s2n_stuffer_write_uint32(&conn->handshake.io, ticket_fields.ticket_age_add));

    /* Write ticket nonce */
    uint8_t nonce_data[sizeof(uint16_t)] = { 0 };
    struct s2n_blob nonce = { 0 };
    GUARD(s2n_blob_init(&nonce, nonce_data, sizeof(nonce_data)));
    GUARD_AS_POSIX(s2n_generate_ticket_nonce(conn->tickets_sent, &nonce));
    GUARD(s2n_stuffer_write_uint8(&conn->handshake.io, nonce.size));
    GUARD(s2n_stuffer_write_bytes(&conn->handshake.io, nonce.data, nonce.size));

    /* Derive individual session ticket secret */
    s2n_tls13_connection_keys(secrets, conn);
    struct s2n_blob master_secret = { 0 };
    GUARD(s2n_blob_init(&master_secret, conn->resumption_master_secret, sizeof(conn->resumption_master_secret)));
    uint8_t session_secret_data[S2N_TLS13_SECRET_MAX_LEN] = { 0 };
    GUARD(s2n_blob_init(&ticket_fields.session_secret, session_secret_data, secrets.size));
    GUARD_AS_POSIX(s2n_tls13_derive_session_ticket_secret(&secrets, &master_secret, &nonce, &ticket_fields.session_secret));

    /* Create ticket */
    uint8_t ticket_data[S2N_MAX_TICKET_SIZE_IN_BYTES] = { 0 };
    struct s2n_blob ticket_blob = { 0 };
    struct s2n_stuffer session_ticket = { 0 };
    GUARD(s2n_blob_init(&ticket_blob, ticket_data, sizeof(ticket_data)));
    GUARD(s2n_stuffer_init(&session_ticket, &ticket_blob));
    GUARD(s2n_encrypt_session_ticket(conn, &ticket_fields, &session_ticket));

    /* Write session ticket */
    ENSURE_POSIX(s2n_stuffer_data_available(&session_ticket) <= UINT8_MAX, S2N_ERR_SAFETY);
    GUARD(s2n_stuffer_write_uint8(&conn->handshake.io, s2n_stuffer_data_available(&session_ticket)));
    GUARD(s2n_stuffer_write(&conn->handshake.io, &session_ticket.blob));

    /* Write size of new session ticket extensions */
    GUARD(s2n_stuffer_write_uint16(&conn->handshake.io, 0));

    GUARD(s2n_stuffer_write_vector_size(&message_size));

    ENSURE_POSIX(conn->tickets_sent < UINT16_MAX, S2N_ERR_INTEGER_OVERFLOW);
    conn->tickets_sent++;

    return S2N_SUCCESS;
}
