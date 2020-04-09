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

#include "stuffer/s2n_stuffer.h"

#include "tls/s2n_tls_parameters.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_tls.h"
#include "tls/extensions/s2n_server_session_ticket.h"

#define s2n_server_can_send_nst(conn) (s2n_server_sending_nst((conn)) && \
        (conn)->actual_protocol_version < S2N_TLS13)

int s2n_recv_server_session_ticket_ext(struct s2n_connection *conn, struct s2n_stuffer *extension)
{
    conn->session_ticket_status = S2N_NEW_TICKET;

    return 0;
}

int s2n_send_server_session_ticket_ext(struct s2n_connection *conn, struct s2n_stuffer *out)
{
    if(s2n_server_can_send_nst(conn)){
        GUARD(s2n_stuffer_write_uint16(out, TLS_EXTENSION_SESSION_TICKET));
        GUARD(s2n_stuffer_write_uint16(out, 0));
    }

    return 0;
}

uint16_t s2n_server_session_ticket_ext_size(struct s2n_connection *conn)
{
    if (s2n_server_can_send_nst(conn)) {
        /* 2 for extension type. 2 for extension length of 0 */
        return 4;
    }

    return 0;
}
