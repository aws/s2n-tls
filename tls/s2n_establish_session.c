/*
 * Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

#include <stdint.h>
#include <s2n.h>

#include "error/s2n_errno.h"

#include "stuffer/s2n_stuffer.h"

#include "tls/s2n_connection.h"
#include "tls/s2n_tls.h"

#include "utils/s2n_array.h"


/* Establishing a session requires reading the CLIENT_HELLO message and then generating security parameters.
 *
 * S2N supports resuming sessions under TLS1.2 if the client sends a session ID. The server can lookup a
 * provided session ID in its cache. */
int s2n_establish_session(struct s2n_connection *conn)
{
    GUARD(s2n_conn_set_handshake_read_block(conn));

    /* Start by receiving and processing the entire CLIENT_HELLO message */
    if (!conn->handshake.client_hello_received) {
        GUARD(s2n_client_hello_recv(conn));
        conn->handshake.client_hello_received = 1;
    }

    /* Next negotiate session security parameters. These could be generated, or retrieved from a cache
     * based on the client's session id. This step uses data obtained from the CLIENT_HELLO message,
     * which is why we process it here.
     * This function won't block, it will fail and set s2n_errno accordingly. */
    GUARD(s2n_conn_set_handshake_type(conn));

    if (conn->client_hello_version != S2N_SSLv2)
    {
        /* We've selected the parameters for the handshake, update the required hashes for this connection */
        GUARD(s2n_conn_update_required_handshake_hashes(conn));
    }

    GUARD(s2n_conn_clear_handshake_read_block(conn));

    return 0;
}

