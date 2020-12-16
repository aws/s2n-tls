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
#include <stdint.h>

#include "tls/s2n_tls.h"
#include "tls/extensions/s2n_server_psk.h"

#include "utils/s2n_safety.h"

static bool s2n_server_psk_should_send(struct s2n_connection *conn);
static int s2n_server_psk_send(struct s2n_connection *conn, struct s2n_stuffer *out);
static int s2n_server_psk_recv(struct s2n_connection *conn, struct s2n_stuffer *extension);

const s2n_extension_type s2n_server_psk_extension = {
    .iana_value = TLS_EXTENSION_PRE_SHARED_KEY,
    .is_response = true,
    .send = s2n_server_psk_send,
    .recv = s2n_server_psk_recv,
    .should_send = s2n_server_psk_should_send,
    .if_missing = s2n_extension_noop_if_missing,
};

static bool s2n_server_psk_should_send(struct s2n_connection *conn)
{
    /* Only send a server pre_shared_key extension if a chosen PSK is set on the connection */
    return conn && s2n_connection_get_protocol_version(conn) >= S2N_TLS13
            && conn->psk_params.chosen_psk;
}

static int s2n_server_psk_send(struct s2n_connection *conn, struct s2n_stuffer *out)
{
    notnull_check(conn);

    /* Send the index of the chosen PSK that is stored on the connection. */
    GUARD(s2n_stuffer_write_uint16(out, conn->psk_params.chosen_psk_wire_index));

    return S2N_SUCCESS;
}

static int s2n_server_psk_recv(struct s2n_connection *conn, struct s2n_stuffer *extension)
{
    notnull_check(conn);

    if (s2n_connection_get_protocol_version(conn) < S2N_TLS13) {
        return S2N_SUCCESS;
    }

    uint16_t chosen_psk_wire_index;
    GUARD(s2n_stuffer_read_uint16(extension, &chosen_psk_wire_index));

    /* From RFC section: https://tools.ietf.org/html/rfc8446#section-4.2.11 
     * Clients MUST verify that the server's selected identity is within the range supplied by the client 
     * */
    ENSURE_POSIX(chosen_psk_wire_index < conn->psk_params.psk_list.len, S2N_ERR_INVALID_ARGUMENT);
    conn->psk_params.chosen_psk_wire_index = chosen_psk_wire_index;

    /* Set the chosen PSK pointer to the PSK at the index received */
    GUARD_AS_POSIX(s2n_array_get(&conn->psk_params.psk_list, conn->psk_params.chosen_psk_wire_index,
                                 (void **)&conn->psk_params.chosen_psk));

    /* Wipe the PSKs not chosen */
    GUARD_AS_POSIX(s2n_psk_parameters_free_unused_psks(&conn->psk_params));

    return S2N_SUCCESS;
}
