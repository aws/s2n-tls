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

#include "testlib/s2n_post_handshake_testlib.h"

#include <sys/param.h>

#include "api/s2n.h"
#include "error/s2n_errno.h"
#include "stuffer/s2n_stuffer.h"
#include "testlib/s2n_mem_testlib.h"
#include "testlib/s2n_testlib.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_record.h"
#include "tls/s2n_tls.h"
#include "utils/s2n_blob.h"
#include "utils/s2n_mem.h"
#include "utils/s2n_safety.h"

S2N_RESULT s2n_test_send_records(struct s2n_connection *conn,
        struct s2n_stuffer messages, uint32_t fragment_size)
{
    RESULT_ENSURE_REF(conn);
    conn->max_outgoing_fragment_length = fragment_size;

    DEFER_CLEANUP(struct s2n_blob record_data = { 0 }, s2n_free);
    RESULT_GUARD_POSIX(s2n_alloc(&record_data, fragment_size));

    s2n_blocked_status blocked = S2N_NOT_BLOCKED;
    uint32_t remaining = 0;
    while ((remaining = s2n_stuffer_data_available(&messages)) > 0) {
        record_data.size = MIN(record_data.size, remaining);
        RESULT_GUARD_POSIX(s2n_stuffer_read(&messages, &record_data));
        RESULT_GUARD(s2n_record_write(conn, TLS_HANDSHAKE, &record_data));
        RESULT_GUARD_POSIX(s2n_flush(conn, &blocked));
    };

    return S2N_RESULT_OK;
}

S2N_RESULT s2n_test_basic_recv(struct s2n_connection *sender,
        struct s2n_connection *receiver)
{
    RESULT_ENSURE_REF(sender);
    RESULT_ENSURE_REF(receiver);

    uint8_t app_data[1] = { 0 };
    s2n_blocked_status blocked = S2N_NOT_BLOCKED;

    int send_ret = s2n_send(sender, app_data, sizeof(app_data), &blocked);
    RESULT_GUARD_POSIX(send_ret);
    RESULT_ENSURE_EQ(send_ret, sizeof(app_data));

    /* Wipe any allocations that happened during the priming s2n_send so that
     * mem-test assertions after the recv only see allocations caused by recv. */
    RESULT_GUARD(s2n_mem_test_wipe_callbacks());

    int recv_ret = s2n_recv(receiver, app_data, sizeof(app_data), &blocked);
    RESULT_GUARD_POSIX(recv_ret);
    RESULT_ENSURE_EQ(recv_ret, sizeof(app_data));

    return S2N_RESULT_OK;
}

S2N_RESULT s2n_test_blocking_recv(struct s2n_connection *sender,
        struct s2n_connection *receiver,
        struct s2n_test_io_stuffer_pair *io_pair)
{
    RESULT_ENSURE_REF(sender);
    RESULT_ENSURE_REF(receiver);
    RESULT_ENSURE_REF(io_pair);

    uint8_t app_data[1] = { 0 };
    s2n_blocked_status blocked = S2N_NOT_BLOCKED;

    int send_ret = s2n_send(sender, app_data, sizeof(app_data), &blocked);
    RESULT_GUARD_POSIX(send_ret);
    RESULT_ENSURE_EQ(send_ret, sizeof(app_data));

    /* Wipe any allocations that happened during the priming s2n_send so that
     * mem-test assertions after the recv only see allocations caused by recv. */
    RESULT_GUARD(s2n_mem_test_wipe_callbacks());

    /* Modify the stuffer's write_cursor to make only one byte
     * of the socket / input data available at a time.
     */
    struct s2n_stuffer *in = &io_pair->client_in;
    if (receiver->mode == S2N_SERVER) {
        in = &io_pair->server_in;
    }
    uint32_t *write_cursor = &in->write_cursor;
    uint32_t *read_cursor = &in->read_cursor;
    RESULT_ENSURE_GT(write_cursor, read_cursor);
    uint32_t saved_write_cursor = *write_cursor;
    RESULT_ENSURE_GT(saved_write_cursor, 0);
    *write_cursor = *read_cursor + 1;

    while (s2n_recv(receiver, app_data, sizeof(app_data), &blocked) < 0) {
        RESULT_ENSURE_EQ(blocked, S2N_BLOCKED_ON_READ);
        RESULT_ENSURE_EQ(s2n_errno, S2N_ERR_IO_BLOCKED);
        (*write_cursor)++;
        RESULT_ENSURE_LTE(*write_cursor, saved_write_cursor);
    }
    RESULT_ENSURE_EQ(*write_cursor, saved_write_cursor);

    return S2N_RESULT_OK;
}

S2N_RESULT s2n_test_init_sender_and_receiver(struct s2n_config *config,
        struct s2n_connection *sender, struct s2n_connection *receiver,
        struct s2n_test_io_stuffer_pair *io_pair)
{
    RESULT_ENSURE_REF(config);
    RESULT_ENSURE_REF(sender);
    RESULT_ENSURE_REF(receiver);
    RESULT_ENSURE_REF(io_pair);

    RESULT_GUARD_POSIX(s2n_connection_set_config(sender, config));
    RESULT_GUARD_POSIX(s2n_connection_set_all_protocol_versions(sender, S2N_TLS13));
    RESULT_GUARD(s2n_connection_set_secrets(sender));
    RESULT_GUARD_POSIX(s2n_connection_set_blinding(sender, S2N_SELF_SERVICE_BLINDING));

    RESULT_GUARD_POSIX(s2n_connection_set_config(receiver, config));
    RESULT_GUARD_POSIX(s2n_connection_set_all_protocol_versions(receiver, S2N_TLS13));
    RESULT_GUARD(s2n_connection_set_secrets(receiver));
    RESULT_GUARD_POSIX(s2n_connection_set_blinding(receiver, S2N_SELF_SERVICE_BLINDING));

    RESULT_GUARD(s2n_io_stuffer_pair_init(io_pair));
    if (sender->mode == S2N_SERVER) {
        RESULT_GUARD(s2n_connections_set_io_stuffer_pair(receiver, sender, io_pair));
    } else {
        RESULT_GUARD(s2n_connections_set_io_stuffer_pair(sender, receiver, io_pair));
    }

    /* Send and receive to initialize io buffers */
    RESULT_GUARD(s2n_test_basic_recv(sender, receiver));

    return S2N_RESULT_OK;
}
