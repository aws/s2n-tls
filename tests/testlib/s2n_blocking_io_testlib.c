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

#include "testlib/s2n_blocking_io_testlib.h"

#include <errno.h>

#include "api/s2n.h"
#include "testlib/s2n_testlib.h"
#include "utils/s2n_safety.h"

static int s2n_blocking_read(void *io_context, uint8_t *buf, uint32_t len)
{
    struct s2n_blocking_io_wrapper *context = (struct s2n_blocking_io_wrapper *) io_context;
    if (context->times_recv_blocked < S2N_BLOCKING_IO_TIMES_TO_BLOCK) {
        context->times_recv_blocked++;
        errno = EAGAIN;
        return -1;
    }
    context->times_recv_blocked = 0;
    return context->inner_recv(context->inner_recv_ctx, buf, len);
}

static int s2n_blocking_write(void *io_context, const uint8_t *buf, uint32_t len)
{
    struct s2n_blocking_io_wrapper *context = (struct s2n_blocking_io_wrapper *) io_context;
    if (context->times_send_blocked < S2N_BLOCKING_IO_TIMES_TO_BLOCK) {
        context->times_send_blocked++;
        errno = EAGAIN;
        return -1;
    }
    context->times_send_blocked = 0;
    return context->inner_send(context->inner_send_ctx, buf, len);
}

S2N_RESULT s2n_connections_set_blocking_io_pair(
        struct s2n_blocking_io_wrapper_pair *io_context,
        struct s2n_connection *client_conn,
        struct s2n_connection *server_conn,
        struct s2n_test_io_stuffer_pair *io_pair)
{
    RESULT_ENSURE_REF(io_context);
    RESULT_ENSURE_REF(client_conn);
    RESULT_ENSURE_REF(server_conn);
    RESULT_ENSURE_REF(io_pair);

    RESULT_GUARD(s2n_io_stuffer_pair_init(io_pair));
    RESULT_GUARD(s2n_connections_set_io_stuffer_pair(client_conn, server_conn, io_pair));

    io_context->client = (struct s2n_blocking_io_wrapper){
        .inner_recv = client_conn->recv,
        .inner_send = client_conn->send,
        .inner_recv_ctx = client_conn->recv_io_context,
        .inner_send_ctx = client_conn->send_io_context,
    };

    RESULT_GUARD_POSIX(s2n_connection_set_recv_cb(client_conn, s2n_blocking_read));
    RESULT_GUARD_POSIX(s2n_connection_set_recv_ctx(client_conn, &io_context->client));
    RESULT_GUARD_POSIX(s2n_connection_set_send_cb(client_conn, s2n_blocking_write));
    RESULT_GUARD_POSIX(s2n_connection_set_send_ctx(client_conn, &io_context->client));

    io_context->server = (struct s2n_blocking_io_wrapper){
        .inner_recv = server_conn->recv,
        .inner_send = server_conn->send,
        .inner_recv_ctx = server_conn->recv_io_context,
        .inner_send_ctx = server_conn->send_io_context,
    };

    RESULT_GUARD_POSIX(s2n_connection_set_recv_cb(server_conn, s2n_blocking_read));
    RESULT_GUARD_POSIX(s2n_connection_set_recv_ctx(server_conn, &io_context->server));
    RESULT_GUARD_POSIX(s2n_connection_set_send_cb(server_conn, s2n_blocking_write));
    RESULT_GUARD_POSIX(s2n_connection_set_send_ctx(server_conn, &io_context->server));

    return S2N_RESULT_OK;
}
