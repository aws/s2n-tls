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

#include "s2n_test.h"

#include "testlib/s2n_testlib.h"

#include <stdint.h>
#include <stdlib.h>

#include <s2n.h>

#include "crypto/s2n_fips.h"

#include "tls/s2n_cipher_suites.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_handshake.h"
#include "tls/s2n_tls13.h"

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

int s2n_test_write_header(struct s2n_stuffer *output, uint8_t record_type, uint8_t message_type)
{
    GUARD(s2n_stuffer_write_uint8(output, record_type));

    /* TLS1.2 protocol version */
    GUARD(s2n_stuffer_write_uint8(output, 3));
    GUARD(s2n_stuffer_write_uint8(output, 3));

    if (record_type == TLS_HANDSHAKE) {
        /* Total message size */
        GUARD(s2n_stuffer_write_uint16(output, 4));

        GUARD(s2n_stuffer_write_uint8(output, message_type));

        /* Handshake message data size */
        GUARD(s2n_stuffer_write_uint24(output, 0));
        return 0;
    }

    if (record_type == TLS_CHANGE_CIPHER_SPEC) {
        /* Total message size */
        GUARD(s2n_stuffer_write_uint16(output, 1));

        /* change spec is always just 0x01 */
        GUARD(s2n_stuffer_write_uint8(output, 1));
        return 0;
    }

    return 0;
}

int main(int argc, char **argv)
{
    BEGIN_TEST();

    /* Construct an array of all valid tls1.3 handshake_types */
    uint16_t valid_tls13_handshakes[S2N_HANDSHAKES_COUNT];
    int valid_tls13_handshakes_size = 0;
    for (int i = 0; i < S2N_HANDSHAKES_COUNT; i++) {
        if( memcmp(tls13_handshakes, invalid_handshake, S2N_MAX_HANDSHAKE_LENGTH) != 0) {
            valid_tls13_handshakes[valid_tls13_handshakes_size] = i;
            valid_tls13_handshakes_size++;
        }
    }

    /* Use handler stubs to avoid errors in handler implementation */
    for (int i = 0; i < sizeof(tls13_state_machine) / sizeof(struct s2n_handshake_action); i++) {
        tls13_state_machine[i].handler[0] = s2n_test_handler;
        tls13_state_machine[i].handler[1] = s2n_test_handler;
    }

    /* Test: When using TLS 1.3, use the new state machine and handshakes */
    {
        struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT);
        conn->actual_protocol_version = S2N_TLS13;
        EXPECT_EQUAL(ACTIVE_STATE_MACHINE(conn), tls13_state_machine);
        EXPECT_EQUAL(ACTIVE_HANDSHAKES(conn), tls13_handshakes);
        EXPECT_SUCCESS(s2n_connection_free(conn));
    }

    /* Test: TLS1.3 server does not wait for client cipher change requests */
    {
        struct s2n_connection *conn = s2n_connection_new(S2N_SERVER);
        conn->actual_protocol_version = S2N_TLS13;

        for (int i = 0; i < valid_tls13_handshakes_size; i++) {
            int handshake = valid_tls13_handshakes[i];

            conn->handshake.handshake_type = handshake;

            for (int j = 0; j < S2N_MAX_HANDSHAKE_LENGTH; j++) {
                if (tls13_handshakes[i][j] == CLIENT_CHANGE_CIPHER_SPEC) {
                    conn->handshake.message_number = j - 1;

                    EXPECT_SUCCESS(s2n_advance_message(conn));

                    EXPECT_EQUAL(conn->handshake.message_number, j + 1);
                    EXPECT_NOT_EQUAL(ACTIVE_MESSAGE(conn), CLIENT_CHANGE_CIPHER_SPEC);

                    break;
                }
            }
        }

        EXPECT_SUCCESS(s2n_connection_free(conn));
    }

    /* Test: TLS1.3 server does not skip server cipher change requests */
    {
        struct s2n_connection *conn = s2n_connection_new(S2N_SERVER);
        conn->actual_protocol_version = S2N_TLS13;

        for (int i = 0; i < valid_tls13_handshakes_size; i++) {
            int handshake = valid_tls13_handshakes[i];

            conn->handshake.handshake_type = handshake;

            for (int j = 0; j < S2N_MAX_HANDSHAKE_LENGTH; j++) {
                if (tls13_handshakes[i][j] == SERVER_CHANGE_CIPHER_SPEC) {
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

    /* Test: TLS1.3 client does not wait for server cipher change requests */
    {
        struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT);
        conn->actual_protocol_version = S2N_TLS13;

        for (int i = 0; i < valid_tls13_handshakes_size; i++) {
            int handshake = valid_tls13_handshakes[i];

            conn->handshake.handshake_type = handshake;

            for (int j = 0; j < S2N_MAX_HANDSHAKE_LENGTH; j++) {
                if (tls13_handshakes[i][j] == SERVER_CHANGE_CIPHER_SPEC) {
                    conn->handshake.message_number = j - 1;

                    EXPECT_SUCCESS(s2n_advance_message(conn));

                    EXPECT_EQUAL(conn->handshake.message_number, j + 1);
                    EXPECT_NOT_EQUAL(ACTIVE_MESSAGE(conn), SERVER_CHANGE_CIPHER_SPEC);

                    break;
                }
            }
        }

        EXPECT_SUCCESS(s2n_connection_free(conn));
    }

    /* Test: TLS1.3 client does not skip client cipher change requests */
    {
        struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT);
        conn->actual_protocol_version = S2N_TLS13;

        for (int i = 0; i < valid_tls13_handshakes_size; i++) {
            int handshake = valid_tls13_handshakes[i];

            conn->handshake.handshake_type = handshake;

            for (int j = 0; j < S2N_MAX_HANDSHAKE_LENGTH; j++) {
                if (tls13_handshakes[i][j] == CLIENT_CHANGE_CIPHER_SPEC) {
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

    /* Test: TLS1.3 client can receive a server cipher change spec at any time. */
    {
        struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT);
        conn->actual_protocol_version = S2N_TLS13;

        struct s2n_stuffer input;
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&input, 0));
        EXPECT_SUCCESS(s2n_connection_set_io_stuffers(&input, NULL, conn));

        GUARD(s2n_setup_handler_to_expect(SERVER_CHANGE_CIPHER_SPEC, S2N_CLIENT));

        for (int i = 0; i < valid_tls13_handshakes_size; i++) {
            int handshake = valid_tls13_handshakes[i];

            conn->handshake.handshake_type = handshake;
            conn->in_status = ENCRYPTED;

            for (int j = 1; j < S2N_MAX_HANDSHAKE_LENGTH; j++) {
                conn->handshake.message_number = j;

                EXPECT_SUCCESS(s2n_test_write_header(&input, TLS_CHANGE_CIPHER_SPEC, 0));

                EXPECT_SUCCESS(handshake_read_io(conn));

                EXPECT_EQUAL(conn->handshake.message_number, j);
                EXPECT_FALSE(unexpected_handler_called);
                EXPECT_TRUE(expected_handler_called);

                EXPECT_SUCCESS(s2n_stuffer_wipe(&input));
                break;
            }
        }

        EXPECT_SUCCESS(s2n_stuffer_free(&input));
        EXPECT_SUCCESS(s2n_connection_free(conn));
    }

    /* Test: TLS1.3 server can receive a client cipher change request at any time. */
    {
        struct s2n_connection *conn = s2n_connection_new(S2N_SERVER);
        conn->actual_protocol_version = S2N_TLS13;

        struct s2n_stuffer input;
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&input, 0));
        EXPECT_SUCCESS(s2n_connection_set_io_stuffers(&input, NULL, conn));

        GUARD(s2n_setup_handler_to_expect(CLIENT_CHANGE_CIPHER_SPEC, S2N_SERVER));

        for (int i = 0; i < valid_tls13_handshakes_size; i++) {
            int handshake = valid_tls13_handshakes[i];

            conn->handshake.handshake_type = handshake;
            conn->in_status = ENCRYPTED;

            for (int j = 1; j < S2N_MAX_HANDSHAKE_LENGTH; j++) {
                conn->handshake.message_number = j;

                EXPECT_SUCCESS(s2n_test_write_header(&input, TLS_CHANGE_CIPHER_SPEC, 0));

                EXPECT_SUCCESS(handshake_read_io(conn));

                EXPECT_EQUAL(conn->handshake.message_number, j);
                EXPECT_FALSE(unexpected_handler_called);
                EXPECT_TRUE(expected_handler_called);

                EXPECT_SUCCESS(s2n_stuffer_wipe(&input));
                break;
            }
        }

        EXPECT_SUCCESS(s2n_stuffer_free(&input));
        EXPECT_SUCCESS(s2n_connection_free(conn));
    }

    /* Test: TLS1.3 s2n_conn_set_handshake_type only sets FULL_HANDSHAKE */
    {
        struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT);

        /* Ensure WITH_SESSION_TICKETS is set */
        conn->config->use_tickets = 1;
        conn->session_ticket_status = S2N_NEW_TICKET;

        /* Ensure CLIENT_AUTH is set */
        conn->config->client_cert_auth_type = S2N_CERT_AUTH_REQUIRED;

        /* Ensure TLS12_PERFECT_FORWARD_SECRECY is set by choosing a cipher suite with is_ephemeral=1 on the kex */
        conn->secure.cipher_suite = &s2n_dhe_rsa_with_chacha20_poly1305_sha256;

        /* Ensure OCSP_STATUS is set by setting the connection status_type */
        conn->status_type = S2N_STATUS_REQUEST_OCSP;

        /* Verify setup: tls1.2 DOES set the flags */
        conn->actual_protocol_version = S2N_TLS12;
        EXPECT_SUCCESS(s2n_conn_set_handshake_type(conn));
        EXPECT_TRUE(conn->handshake.handshake_type & TLS12_PERFECT_FORWARD_SECRECY );
        EXPECT_TRUE(conn->handshake.handshake_type & OCSP_STATUS );
        EXPECT_TRUE(conn->handshake.handshake_type & WITH_SESSION_TICKET );
        EXPECT_TRUE(conn->handshake.handshake_type & CLIENT_AUTH );

        /* Verify that tls1.3 DOES NOT set the flags */
        conn->actual_protocol_version = S2N_TLS13;
        EXPECT_SUCCESS(s2n_conn_set_handshake_type(conn));
        EXPECT_EQUAL(conn->handshake.handshake_type, NEGOTIATED | FULL_HANDSHAKE);

        EXPECT_SUCCESS(s2n_connection_free(conn));
    }

    END_TEST();
    return 0;
}
