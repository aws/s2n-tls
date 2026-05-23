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

#pragma once

#include "api/s2n.h"
#include "testlib/s2n_testlib.h"
#include "utils/s2n_result.h"

/* Number of times each read or write call blocks before succeeding.
 * Exercising the blocked-IO resume code path at least once is the important
 * invariant; we keep this small so tests stay fast. Two blocks per call lets
 * us verify that resume works repeatedly at the same boundary without paying
 * for additional redundant state-machine reentries.
 */
#define S2N_BLOCKING_IO_TIMES_TO_BLOCK 2

/* Wraps a connection's inner recv/send callbacks so that every read or write
 * returns -1 with errno = EAGAIN a fixed number of times before the inner
 * callback is invoked. Used to force handshakes and record IO to retry on
 * blocked IO.
 */
struct s2n_blocking_io_wrapper {
    uint8_t times_recv_blocked;
    uint8_t times_send_blocked;
    s2n_recv_fn *inner_recv;
    s2n_send_fn *inner_send;
    void *inner_recv_ctx;
    void *inner_send_ctx;
};

struct s2n_blocking_io_wrapper_pair {
    struct s2n_blocking_io_wrapper client;
    struct s2n_blocking_io_wrapper server;
};

/* Installs blocking IO wrappers on both connections after initializing the
 * underlying IO stuffer pair. The io_context must outlive the connections.
 */
S2N_RESULT s2n_connections_set_blocking_io_pair(
        struct s2n_blocking_io_wrapper_pair *io_context,
        struct s2n_connection *client_conn,
        struct s2n_connection *server_conn,
        struct s2n_test_io_stuffer_pair *io_pair);
