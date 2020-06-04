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

#include "testlib/s2n_testlib.h"

static int s2n_try_negotiate(struct s2n_connection *conn, bool *is_done, bool peer_is_done)
{
    s2n_blocked_status blocked;
    int rc = s2n_negotiate(conn, &blocked);

    /* If we succeeded, we're done. */
    if(rc == S2N_SUCCESS) {
        *is_done = true;
        return S2N_SUCCESS;
    }

    /* If we failed for any error other than 'blocked', propagate the error. */
    if(s2n_error_get_type(s2n_errno) != S2N_ERR_T_BLOCKED) {
        S2N_ERROR_PRESERVE_ERRNO();
    }

    /* If we're blocked but our peer is done writing, propagate the error. */
    if(peer_is_done) {
        S2N_ERROR_PRESERVE_ERRNO();
    }

    *is_done = false;
    return S2N_SUCCESS;
}

int s2n_negotiate_test_server_and_client(struct s2n_connection *server_conn, struct s2n_connection *client_conn)
{
    bool server_done = 0, client_done = 0;

    do {
        GUARD(s2n_try_negotiate(client_conn, &client_done, server_done));
        GUARD(s2n_try_negotiate(server_conn, &server_done, client_done));
    } while (!client_done || !server_done);

    return S2N_SUCCESS;
}

int s2n_shutdown_test_server_and_client(struct s2n_connection *server_conn, struct s2n_connection *client_conn)
{
    int server_rc = -1;
    int client_rc = -1;
    s2n_blocked_status server_blocked;
    s2n_blocked_status client_blocked;
    int server_done = 0;
    int client_done = 0;

    do {
        if (!server_done) {
            s2n_errno = S2N_ERR_T_OK;
            server_rc = s2n_shutdown(server_conn, &server_blocked);

            if (s2n_error_get_type(s2n_errno) != S2N_ERR_T_BLOCKED || client_done) {
/* Success, fatal error, or the peer is done and we're still blocked. */
                server_done = 1;
            }
        }
        if (!client_done) {
            s2n_errno = S2N_ERR_T_OK;
            client_rc = s2n_shutdown(client_conn, &client_blocked);

            if (s2n_error_get_type(s2n_errno) != S2N_ERR_T_BLOCKED || server_done) {
/* Success, fatal error, or the peer is done and we're still blocked. */
                client_done = 1;
            }
        }
    } while (!client_done || !server_done);

    int rc = (server_rc == 0 && client_rc == 0) ? 0 : -1;
    return rc;
}
