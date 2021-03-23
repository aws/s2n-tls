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

#include "tls/s2n_early_data.h"

#include "tls/s2n_connection.h"
#include "utils/s2n_safety.h"
#include "utils/s2n_mem.h"

int s2n_end_of_early_data_send(struct s2n_connection *conn)
{
    if (conn->early_data_expected) {
        POSIX_GUARD(s2n_stuffer_wipe(&conn->handshake.io));
        POSIX_BAIL(S2N_ERR_EARLY_DATA_BLOCKED);
    }

    POSIX_GUARD_RESULT(s2n_connection_set_early_data_state(conn, S2N_END_OF_EARLY_DATA));
    return S2N_SUCCESS;
}

int s2n_end_of_early_data_recv(struct s2n_connection *conn)
{
    POSIX_GUARD_RESULT(s2n_connection_set_early_data_state(conn, S2N_END_OF_EARLY_DATA));
    return S2N_SUCCESS;
}

static bool s2n_is_early_data_io(struct s2n_connection *conn)
{
    if (s2n_conn_get_current_message_type(conn) == APPLICATION_DATA) {
        return false;
    }

    /* It would be more accurate to not include this check.
     * However, before the early data feature was added, s2n_send and s2n_recv
     * did not verify that they were being called after a complete handshake.
     * Enforcing that broke several S2N tests, and might have broken customers too.
     *
     * Therefore, only consider this early data if the customer has indicated that
     * they are aware of early data, either because early data is currently expected
     * or early data is in a state that indicates that early data was previously expected.
     */
    if (conn->early_data_expected
            || (conn->mode == S2N_CLIENT && conn->early_data_state == S2N_EARLY_DATA_REQUESTED)
            || conn->early_data_state == S2N_EARLY_DATA_ACCEPTED
            || conn->early_data_state == S2N_END_OF_EARLY_DATA) {
        return true;
    }
    return false;
}

S2N_RESULT s2n_early_data_record_bytes(struct s2n_connection *conn, ssize_t data_len)
{
    RESULT_ENSURE_REF(conn);
    if (!s2n_is_early_data_io(conn)) {
        return S2N_RESULT_OK;
    }

    /* Ensure the bytes read are within the bounds of what we can actually record. */
    if (data_len > (UINT64_MAX - conn->early_data_bytes)) {
        conn->early_data_bytes = UINT64_MAX;
        BAIL(S2N_ERR_INTEGER_OVERFLOW);
    }

    /* Record the early data bytes read, even if they exceed the max_early_data_size.
     * This will ensure that if this method is called again, it will fail again:
     * Once we receive too many bytes, we can't proceed with the connection. */
    conn->early_data_bytes += data_len;

    uint32_t max_early_data_size = 0;
    RESULT_GUARD_POSIX(s2n_connection_get_max_early_data_size(conn, &max_early_data_size));
    RESULT_ENSURE(conn->early_data_bytes <= max_early_data_size, S2N_ERR_MAX_EARLY_DATA_SIZE);

    return S2N_RESULT_OK;
}

S2N_RESULT s2n_early_data_validate_send(struct s2n_connection *conn, uint32_t bytes_to_send)
{
    RESULT_ENSURE_REF(conn);
    if (!s2n_is_early_data_io(conn)) {
        return S2N_RESULT_OK;
    }

    RESULT_ENSURE(conn->early_data_expected, S2N_ERR_EARLY_DATA_NOT_ALLOWED);
    RESULT_ENSURE(conn->mode == S2N_CLIENT, S2N_ERR_EARLY_DATA_NOT_ALLOWED);
    RESULT_ENSURE(conn->early_data_state == S2N_EARLY_DATA_REQUESTED
            || conn->early_data_state == S2N_EARLY_DATA_ACCEPTED, S2N_ERR_EARLY_DATA_NOT_ALLOWED);

    uint32_t allowed_early_data_size = 0;
    RESULT_GUARD_POSIX(s2n_connection_get_remaining_early_data_size(conn, &allowed_early_data_size));
    RESULT_ENSURE(bytes_to_send <= allowed_early_data_size, S2N_ERR_MAX_EARLY_DATA_SIZE);

    return S2N_RESULT_OK;
}

S2N_RESULT s2n_early_data_validate_recv(struct s2n_connection *conn)
{
    RESULT_ENSURE_REF(conn);
    if (!s2n_is_early_data_io(conn)) {
        return S2N_RESULT_OK;
    }

    RESULT_ENSURE(conn->early_data_expected, S2N_ERR_EARLY_DATA_NOT_ALLOWED);
    RESULT_ENSURE(conn->mode == S2N_SERVER, S2N_ERR_EARLY_DATA_NOT_ALLOWED);
    RESULT_ENSURE(conn->early_data_state == S2N_EARLY_DATA_ACCEPTED, S2N_ERR_EARLY_DATA_NOT_ALLOWED);
    RESULT_ENSURE(s2n_conn_get_current_message_type(conn) == END_OF_EARLY_DATA, S2N_ERR_EARLY_DATA_NOT_ALLOWED);
    return S2N_RESULT_OK;
}
