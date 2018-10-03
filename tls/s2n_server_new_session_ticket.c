/*
 * Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

    GUARD(s2n_encrypt_session_ticket(conn, &to));
    GUARD(s2n_stuffer_write(&conn->handshake.io, &to.blob));

    return 0;
}
