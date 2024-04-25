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

static S2N_RESULT s2n_validate_negotiate_result(bool success, bool peer_is_done, bool *is_done)
{
    /* If we succeeded, we're done. */
    if (success) {
        *is_done = true;
        return S2N_RESULT_OK;
    }

    /* If we failed for any error other than 'blocked', propagate the error. */
    if (s2n_error_get_type(s2n_errno) != S2N_ERR_T_BLOCKED) {
        return S2N_RESULT_ERROR;
    }

    if (s2n_errno == S2N_ERR_ASYNC_BLOCKED) {
        return S2N_RESULT_ERROR;
    }

    /* If we're blocked but our peer is done writing, propagate the error. */
    if (peer_is_done) {
        return S2N_RESULT_ERROR;
    }

    *is_done = false;
    return S2N_RESULT_OK;
}

int s2n_negotiate_test_server_and_client(struct s2n_connection *server_conn, struct s2n_connection *client_conn)
{
    bool server_done = false, client_done = false;
    s2n_blocked_status blocked = S2N_NOT_BLOCKED;

    do {
        bool rc = (s2n_negotiate(client_conn, &blocked) >= S2N_SUCCESS);
        POSIX_GUARD_RESULT(s2n_validate_negotiate_result(rc, server_done, &client_done));

        rc = (s2n_negotiate(server_conn, &blocked) >= S2N_SUCCESS);
        POSIX_GUARD_RESULT(s2n_validate_negotiate_result(rc, client_done, &server_done));
    } while (!client_done || !server_done);

    return S2N_SUCCESS;
}

S2N_RESULT s2n_negotiate_test_server_and_client_with_early_data(struct s2n_connection *server_conn,
        struct s2n_connection *client_conn, struct s2n_blob *early_data_to_send, struct s2n_blob *early_data_received)
{
    s2n_blocked_status blocked = S2N_NOT_BLOCKED;
    ssize_t total_data_sent = 0, total_data_recv = 0;
    ssize_t data_sent = 0, data_recv = 0;

    /* We call s2n_send_early_data and s2n_recv_early_data to handle the early data before
     * calling s2n_negotiate to complete the handshake.
     *
     * s2n_recv_early_data does not indicate success until it receives the EndOfEarlyData message,
     * indicating that the client is done sending early data. However, the client does not send the
     * EndOfEarlyData message until s2n_negotiate is called. Instead, we should consider the
     * server done when it has either read all early data (which may be zero bytes) or has
     * rejected the early data.
     */
    bool server_done = false, client_done = false;
    bool server_early_done = false, client_early_done = false;
    do {
        if (!client_early_done) {
            bool success = s2n_send_early_data(client_conn,
                                   early_data_to_send->data + total_data_sent,
                                   early_data_to_send->size - total_data_sent,
                                   &data_sent, &blocked)
                    == S2N_SUCCESS;
            total_data_sent += data_sent;
            RESULT_GUARD(s2n_validate_negotiate_result(success, false, &client_early_done));
        } else {
            bool success = (s2n_negotiate(client_conn, &blocked) == S2N_SUCCESS);
            RESULT_GUARD(s2n_validate_negotiate_result(success, server_done, &client_done));
        }

        if (!server_early_done) {
            bool success = s2n_recv_early_data(server_conn,
                                   early_data_received->data + total_data_recv,
                                   early_data_received->size - total_data_recv,
                                   &data_recv, &blocked)
                    == S2N_SUCCESS;
            total_data_recv += data_recv;
            RESULT_GUARD(s2n_validate_negotiate_result(success, false, &server_early_done));
        } else {
            bool success = (s2n_negotiate(server_conn, &blocked) == S2N_SUCCESS);
            RESULT_GUARD(s2n_validate_negotiate_result(success, client_done, &server_done));
        }
    } while (!client_done || !server_done);

    early_data_received->size = total_data_recv;
    return S2N_RESULT_OK;
}

S2N_RESULT s2n_negotiate_test_server_and_client_until_message(struct s2n_connection *server_conn,
        struct s2n_connection *client_conn, message_type_t message_type)
{
    bool server_done = false, client_done = false;
    s2n_blocked_status blocked = S2N_NOT_BLOCKED;

    do {
        bool rc = s2n_result_is_ok(s2n_negotiate_until_message(client_conn, &blocked, message_type));
        RESULT_GUARD(s2n_validate_negotiate_result(rc, server_done, &client_done));

        rc = s2n_result_is_ok(s2n_negotiate_until_message(server_conn, &blocked, message_type));
        RESULT_GUARD(s2n_validate_negotiate_result(rc, client_done, &server_done));
    } while (!client_done || !server_done);

    return S2N_RESULT_OK;
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

S2N_RESULT s2n_send_and_recv_test(struct s2n_connection *send_conn, struct s2n_connection *recv_conn)
{
    RESULT_ENSURE_REF(send_conn);
    RESULT_ENSURE_REF(recv_conn);

    s2n_blocked_status blocked = S2N_NOT_BLOCKED;

    const uint8_t send_data[] = "hello world";
    ssize_t send_size = s2n_send(send_conn, send_data, sizeof(send_data), &blocked);
    RESULT_GUARD_POSIX(send_size);
    RESULT_ENSURE_EQ(send_size, sizeof(send_data));

    uint8_t recv_data[sizeof(send_data)] = { 0 };
    ssize_t recv_size = s2n_recv(recv_conn, recv_data, send_size, &blocked);
    RESULT_GUARD_POSIX(recv_size);
    RESULT_ENSURE_EQ(recv_size, send_size);
    RESULT_ENSURE_EQ(memcmp(recv_data, send_data, send_size), 0);

    return S2N_RESULT_OK;
}
