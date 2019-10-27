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

#include <s2n.h>

#include "s2n_test.h"
#include "testlib/s2n_testlib.h"

#include "tls/s2n_connection.h"
#include "tls/s2n_handshake.h"
#include "utils/s2n_safety.h"

/* Just to get access to the static functions / variables we need to test */
#include "tls/s2n_handshake_io.c"

static message_type_t invalid_handshake[S2N_MAX_HANDSHAKE_LENGTH];

static int expected_handler_called;
static int unexpected_handler_called;

static int s2n_test_handler(struct s2n_connection* conn)
{
    unexpected_handler_called = 1;
    return 0;
}

static int s2n_test_expected_handler(struct s2n_connection* conn)
{
    expected_handler_called = 1;
    return 0;
}

static int s2n_setup_handler_to_expect(message_type_t expected, uint8_t direction) {
    for (int i = 0; i < sizeof(tls13_state_machine) / sizeof(struct s2n_handshake_action); i++) {
        tls13_state_machine[i].handler[0] = s2n_test_handler;
        tls13_state_machine[i].handler[1] = s2n_test_handler;
    }

    tls13_state_machine[expected].handler[direction] = s2n_test_expected_handler;

    expected_handler_called = 0;
    unexpected_handler_called = 0;

    return 0;
}

int s2n_write_ccs_message(struct s2n_stuffer *output)
{
    GUARD(s2n_stuffer_write_uint8(output, TLS_CHANGE_CIPHER_SPEC));

    /* TLS1.2 protocol version */
    GUARD(s2n_stuffer_write_uint8(output, 3));
    GUARD(s2n_stuffer_write_uint8(output, 3));

    /* Total message size */
    GUARD(s2n_stuffer_write_uint16(output, 1));

    /* change spec is always just 0x01 */
    GUARD(s2n_stuffer_write_uint8(output, 1));

    return 0;
}

int main(int argc, char **argv)
{
    BEGIN_TEST();

    /* Construct an array of all valid tls1.2 handshake_types */
    uint16_t valid_tls12_handshakes[S2N_HANDSHAKES_COUNT];
    int valid_tls12_handshakes_size = 0;
    for (int i = 0; i < S2N_HANDSHAKES_COUNT; i++) {
        if( memcmp(handshakes, invalid_handshake, S2N_MAX_HANDSHAKE_LENGTH) != 0) {
            valid_tls12_handshakes[valid_tls12_handshakes_size] = i;
            valid_tls12_handshakes_size++;
        }
    }

    /* Test: When using TLS 1.2, use the existing state machine and handshakes */
    {
        struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT);
        conn->actual_protocol_version = S2N_TLS12;
        EXPECT_EQUAL(ACTIVE_STATE_MACHINE(conn), state_machine);
        EXPECT_EQUAL(ACTIVE_HANDSHAKES(conn), handshakes);
        EXPECT_SUCCESS(s2n_connection_free(conn));
    }

    /* Test: TLS1.2 server waits for expected CCS messages */
    {
        struct s2n_connection *conn = s2n_connection_new(S2N_SERVER);
        conn->actual_protocol_version = S2N_TLS12;

        for (int i = 0; i < valid_tls12_handshakes_size; i++) {
            int handshake = valid_tls12_handshakes[i];

            conn->handshake.handshake_type = handshake;

            for (int j = 0; j < S2N_MAX_HANDSHAKE_LENGTH; j++) {
                if (handshakes[i][j] == CLIENT_CHANGE_CIPHER_SPEC) {
                    conn->handshake.message_number = j - 1;

                    EXPECT_SUCCESS(s2n_advance_message(conn));

                    EXPECT_EQUAL(conn->handshake.message_number, j);
                    EXPECT_EQUAL(ACTIVE_MESSAGE(conn), CLIENT_CHANGE_CIPHER_SPEC);

                    break;
                }
            }
        }

        EXPECT_SUCCESS(s2n_connection_free(conn));
    }

    /* Test: TLS1.2 client waits for expected CCS messages */
    {
        struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT);
        conn->actual_protocol_version = S2N_TLS12;

        for (int i = 0; i < valid_tls12_handshakes_size; i++) {
            int handshake = valid_tls12_handshakes[i];

            conn->handshake.handshake_type = handshake;

            for (int j = 0; j < S2N_MAX_HANDSHAKE_LENGTH; j++) {
                if (handshakes[i][j] == SERVER_CHANGE_CIPHER_SPEC) {
                    conn->handshake.message_number = j - 1;

                    EXPECT_SUCCESS(s2n_advance_message(conn));

                    EXPECT_EQUAL(conn->handshake.message_number, j);
                    EXPECT_EQUAL(ACTIVE_MESSAGE(conn), SERVER_CHANGE_CIPHER_SPEC);

                    break;
                }
            }
        }

        EXPECT_SUCCESS(s2n_connection_free(conn));
    }

    /* Test: TLS1.2 client handles expected server CCS messages
     *       but errors on unexpected CCS messages */
    {
        struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT);
        conn->actual_protocol_version = S2N_TLS12;

        struct s2n_stuffer input;
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&input, 0));
        EXPECT_SUCCESS(s2n_connection_set_io_stuffers(&input, NULL, conn));

        EXPECT_SUCCESS(s2n_setup_handler_to_expect(SERVER_CHANGE_CIPHER_SPEC, S2N_CLIENT));

        for (int i = 0; i < valid_tls12_handshakes_size; i++) {
            int handshake = valid_tls12_handshakes[i];

            conn->handshake.handshake_type = handshake;
            conn->in_status = ENCRYPTED;

            for (int j = 1; j < S2N_MAX_HANDSHAKE_LENGTH; j++) {
                conn->handshake.message_number = j;
                EXPECT_SUCCESS(s2n_write_ccs_message(&input));

                if (handshakes[i][j] == SERVER_CHANGE_CIPHER_SPEC) {
                    EXPECT_SUCCESS(handshake_read_io(conn));
                    EXPECT_TRUE(expected_handler_called);
                    EXPECT_FALSE(unexpected_handler_called);
                } else {
                    EXPECT_FAILURE_WITH_ERRNO(handshake_read_io(conn), S2N_ERR_BAD_MESSAGE);
                    EXPECT_FALSE(expected_handler_called);
                    EXPECT_FALSE(unexpected_handler_called);
                }

                EXPECT_SUCCESS(s2n_stuffer_wipe(&input));
                break;
            }
        }

        EXPECT_SUCCESS(s2n_stuffer_free(&input));
        EXPECT_SUCCESS(s2n_connection_free(conn));
    }

    /* Test: TLS1.2 server handles expected client CCS messages
     *       but errors on unexpected CCS messages */
    {
        struct s2n_connection *conn = s2n_connection_new(S2N_SERVER);
        conn->actual_protocol_version = S2N_TLS12;

        struct s2n_stuffer input;
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&input, 0));
        EXPECT_SUCCESS(s2n_connection_set_io_stuffers(&input, NULL, conn));

        EXPECT_SUCCESS(s2n_setup_handler_to_expect(CLIENT_CHANGE_CIPHER_SPEC, S2N_SERVER));

        for (int i = 0; i < valid_tls12_handshakes_size; i++) {
            int handshake = valid_tls12_handshakes[i];

            conn->handshake.handshake_type = handshake;
            conn->in_status = ENCRYPTED;

            for (int j = 1; j < S2N_MAX_HANDSHAKE_LENGTH; j++) {
                conn->handshake.message_number = j;
                EXPECT_SUCCESS(s2n_write_ccs_message(&input));

                if (handshakes[i][j] == CLIENT_CHANGE_CIPHER_SPEC) {
                    EXPECT_SUCCESS(handshake_read_io(conn));
                    EXPECT_TRUE(expected_handler_called);
                    EXPECT_FALSE(unexpected_handler_called);
                } else {
                    EXPECT_FAILURE_WITH_ERRNO(handshake_read_io(conn), S2N_ERR_BAD_MESSAGE);
                    EXPECT_FALSE(expected_handler_called);
                    EXPECT_FALSE(unexpected_handler_called);
                }

                EXPECT_SUCCESS(s2n_stuffer_wipe(&input));
                break;
            }
        }

        EXPECT_SUCCESS(s2n_stuffer_free(&input));
        EXPECT_SUCCESS(s2n_connection_free(conn));
    }

    END_TEST();
    return 0;
}
