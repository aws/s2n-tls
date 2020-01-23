/*
 * Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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
#include <stdint.h>

#include "tls/extensions/s2n_client_session_ticket.h"
#include "tls/s2n_tls.h"
#include "tls/s2n_tls_parameters.h"
#include "tls/s2n_resume.h"

#include "utils/s2n_safety.h"

int s2n_extensions_client_session_ticket_send(struct s2n_connection *conn, struct s2n_stuffer *out)
{
    uint16_t client_ticket_len = conn->client_ticket.size;
    
    GUARD(s2n_stuffer_write_uint16(out, TLS_EXTENSION_SESSION_TICKET));
    GUARD(s2n_stuffer_write_uint16(out, client_ticket_len));
    GUARD(s2n_stuffer_write(out, &conn->client_ticket));

    return 0;
}

int s2n_recv_client_session_ticket_ext(struct s2n_connection *conn, struct s2n_stuffer *extension)
{
    if (conn->config->use_tickets != 1) {
        /* Ignore the extension. */
        return 0;
    }

    /* s2n server does not support session ticket with CLIENT_AUTH enabled */
    if (s2n_connection_is_client_auth_enabled(conn) > 0) {
        return 0;
    }

    if (s2n_stuffer_data_available(extension) == S2N_TICKET_SIZE_IN_BYTES) {
        conn->session_ticket_status = S2N_DECRYPT_TICKET;
        GUARD(s2n_stuffer_copy(extension, &conn->client_ticket_to_decrypt, S2N_TICKET_SIZE_IN_BYTES));
    } else if (s2n_config_is_encrypt_decrypt_key_available(conn->config) == 1) {
        conn->session_ticket_status = S2N_NEW_TICKET;
    }

    return 0;
}
