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
#include "stuffer/s2n_stuffer.h"
#include "testlib/s2n_testlib.h"
#include "utils/s2n_result.h"

/* Write the contents of "messages" as one or more TLS_HANDSHAKE records with
 * the given fragment size. Used by post-handshake receive tests to simulate a
 * peer sending fragmented handshake messages after the handshake completes.
 */
S2N_RESULT s2n_test_send_records(struct s2n_connection *conn,
        struct s2n_stuffer messages, uint32_t fragment_size);

/* Verify that the receiver can receive a single byte sent by the sender.
 * In the process, we also verify that the receiver can receive all previous
 * data sent by the sender, since TCP / TLS messages have a guaranteed order.
 */
S2N_RESULT s2n_test_basic_recv(struct s2n_connection *sender,
        struct s2n_connection *receiver);

/* Like s2n_test_basic_recv, but makes only one byte of data available at a
 * time. This forces s2n_recv to be called repeatedly and verifies that it can
 * resume across calls while handling fragmented post-handshake messages.
 */
S2N_RESULT s2n_test_blocking_recv(struct s2n_connection *sender,
        struct s2n_connection *receiver,
        struct s2n_test_io_stuffer_pair *io_pair);

/* Configure a sender / receiver connection pair for post-handshake receive
 * tests: sets the config, pins the protocol version to TLS 1.3, installs fake
 * secrets, disables blinding, wires up the io stuffer pair, and sends one
 * priming byte in each direction to initialize IO buffers.
 */
S2N_RESULT s2n_test_init_sender_and_receiver(struct s2n_config *config,
        struct s2n_connection *sender, struct s2n_connection *receiver,
        struct s2n_test_io_stuffer_pair *io_pair);
