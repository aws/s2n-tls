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

#include "api/s2n.h"
#include "s2n_test.h"
#include "testlib/s2n_testlib.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_handshake.h"
#include "utils/s2n_safety.h"

/* Just to get access to the static functions / variables we need to test */
#include "tls/s2n_handshake_io.c"

static message_type_t invalid_handshake[S2N_MAX_HANDSHAKE_LENGTH] = { 0 };

static int expected_handler_called;
static int unexpected_handler_called;

static int s2n_test_handler(struct s2n_connection *conn)
{
    unexpected_handler_called = 1;
    return 0;
}

static int s2n_test_expected_handler(struct s2n_connection *conn)
{
    expected_handler_called = 1;
    return 0;
}

static int s2n_setup_handler_to_expect(message_type_t expected, uint8_t direction)
{
    for (int i = 0; i < s2n_array_len(state_machine); i++) {
        state_machine[i].handler[0] = s2n_test_handler;
        state_machine[i].handler[1] = s2n_test_handler;
    }

    state_machine[expected].handler[direction] = s2n_test_expected_handler;

    expected_handler_called = 0;
    unexpected_handler_called = 0;

    return 0;
}

static int s2n_test_write_header(struct s2n_stuffer *output, uint8_t record_type, uint8_t message_type)
{
    POSIX_GUARD(s2n_stuffer_write_uint8(output, record_type));

    /* TLS1.2 protocol version */
    POSIX_GUARD(s2n_stuffer_write_uint8(output, 3));
    POSIX_GUARD(s2n_stuffer_write_uint8(output, 3));

    if (record_type == TLS_HANDSHAKE) {
        /* Total message size */
        POSIX_GUARD(s2n_stuffer_write_uint16(output, 4));

        POSIX_GUARD(s2n_stuffer_write_uint8(output, message_type));

        /* Handshake message data size */
        POSIX_GUARD(s2n_stuffer_write_uint24(output, 0));
        return 0;
    }

    if (record_type == TLS_CHANGE_CIPHER_SPEC) {
        /* Total message size */
        POSIX_GUARD(s2n_stuffer_write_uint16(output, 1));

        /* change spec is always just 0x01 */
        POSIX_GUARD(s2n_stuffer_write_uint8(output, 1));
        return 0;
    }

    return 0;
}

int main(int argc, char **argv)
{
    BEGIN_TEST();
    EXPECT_SUCCESS(s2n_disable_tls13_in_test());

    /* Construct an array of all valid tls1.2 handshake_types */
    uint16_t valid_tls12_handshakes[S2N_HANDSHAKES_COUNT];
    int valid_tls12_handshakes_size = 0;
    for (int i = 0; i < S2N_HANDSHAKES_COUNT; i++) {
        if (memcmp(handshakes[i], invalid_handshake, S2N_MAX_HANDSHAKE_LENGTH) != 0) {
            valid_tls12_handshakes[valid_tls12_handshakes_size] = i;
            valid_tls12_handshakes_size++;
        }
    }
    EXPECT_TRUE(valid_tls12_handshakes_size > 0);
    EXPECT_TRUE(valid_tls12_handshakes_size < S2N_HANDSHAKES_COUNT);

    /* Test: When using TLS 1.2, use the existing state machine and handshakes */
    {
        struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT);
        conn->actual_protocol_version = S2N_TLS12;
        EXPECT_EQUAL(ACTIVE_STATE_MACHINE(conn), state_machine);
        EXPECT_EQUAL(ACTIVE_HANDSHAKES(conn), handshakes);
        EXPECT_SUCCESS(s2n_connection_free(conn));
    };

    /* Test: TLS1.2 server waits for expected CCS messages */
    {
        struct s2n_connection *conn = s2n_connection_new(S2N_SERVER);
        conn->actual_protocol_version = S2N_TLS12;

        for (int i = 0; i < valid_tls12_handshakes_size; i++) {
            int handshake = valid_tls12_handshakes[i];

            conn->handshake.handshake_type = handshake;

            for (int j = 0; j < S2N_MAX_HANDSHAKE_LENGTH; j++) {
                if (handshakes[handshake][j] == CLIENT_CHANGE_CIPHER_SPEC) {
                    conn->handshake.message_number = j - 1;

                    EXPECT_SUCCESS(s2n_advance_message(conn));

                    EXPECT_EQUAL(conn->handshake.message_number, j);
                    EXPECT_EQUAL(ACTIVE_MESSAGE(conn), CLIENT_CHANGE_CIPHER_SPEC);

                    break;
                }
            }
        }

        EXPECT_SUCCESS(s2n_connection_free(conn));
    };

    /* Test: Client CCS messages always come before Client Finished messages */
    {
        for (int i = 0; i < valid_tls12_handshakes_size; i++) {
            int handshake = valid_tls12_handshakes[i];
            /* Initial handshake doesn't contain a CCS message */
            if (handshake == INITIAL) {
                continue;
            }

            bool ccs_encountered = false;

            for (int j = 0; j < S2N_MAX_HANDSHAKE_LENGTH; j++) {
                if (handshakes[handshake][j] == CLIENT_CHANGE_CIPHER_SPEC) {
                    ccs_encountered = true;
                }

                if (handshakes[handshake][j] == CLIENT_FINISHED) {
                    EXPECT_TRUE(ccs_encountered);
                }
            }
            /* Every valid handshake includes a CCS message */
            EXPECT_TRUE(ccs_encountered);
        }
    };

    /* Test: TLS1.2 client waits for expected CCS messages */
    {
        struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT);
        conn->actual_protocol_version = S2N_TLS12;

        for (int i = 0; i < valid_tls12_handshakes_size; i++) {
            int handshake = valid_tls12_handshakes[i];

            conn->handshake.handshake_type = handshake;

            for (int j = 0; j < S2N_MAX_HANDSHAKE_LENGTH; j++) {
                if (handshakes[handshake][j] == SERVER_CHANGE_CIPHER_SPEC) {
                    conn->handshake.message_number = j - 1;

                    EXPECT_SUCCESS(s2n_advance_message(conn));

                    EXPECT_EQUAL(conn->handshake.message_number, j);
                    EXPECT_EQUAL(ACTIVE_MESSAGE(conn), SERVER_CHANGE_CIPHER_SPEC);

                    break;
                }
            }
        }

        EXPECT_SUCCESS(s2n_connection_free(conn));
    };

    /* Test: TLS1.2 client handles expected server CCS messages
     *       but errors on unexpected CCS messages */
    {
        struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT);
        conn->actual_protocol_version = S2N_TLS12;

        struct s2n_stuffer input = { 0 };
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&input, 0));
        EXPECT_SUCCESS(s2n_connection_set_io_stuffers(&input, NULL, conn));

        for (int i = 0; i < valid_tls12_handshakes_size; i++) {
            int handshake = valid_tls12_handshakes[i];

            conn->handshake.handshake_type = handshake;

            for (int j = 1; j < S2N_MAX_HANDSHAKE_LENGTH; j++) {
                EXPECT_SUCCESS(s2n_setup_handler_to_expect(SERVER_CHANGE_CIPHER_SPEC, S2N_CLIENT));
                conn->handshake.message_number = j;
                conn->in_status = ENCRYPTED;

                EXPECT_SUCCESS(s2n_test_write_header(&input, TLS_CHANGE_CIPHER_SPEC, 0));

                if (handshakes[handshake][j] == SERVER_CHANGE_CIPHER_SPEC) {
                    EXPECT_SUCCESS(s2n_handshake_read_io(conn));
                    EXPECT_TRUE(expected_handler_called);
                    EXPECT_FALSE(unexpected_handler_called);
                } else {
                    EXPECT_FAILURE_WITH_ERRNO(s2n_handshake_read_io(conn), S2N_ERR_BAD_MESSAGE);
                    EXPECT_FALSE(expected_handler_called);
                    EXPECT_FALSE(unexpected_handler_called);
                }

                EXPECT_SUCCESS(s2n_stuffer_wipe(&input));
            }
        }

        EXPECT_SUCCESS(s2n_stuffer_free(&input));
        EXPECT_SUCCESS(s2n_connection_free(conn));
    };

    /* Test: TLS1.2 server handles expected client CCS messages
     *       but errors on unexpected CCS messages */
    {
        struct s2n_connection *conn = s2n_connection_new(S2N_SERVER);
        conn->actual_protocol_version = S2N_TLS12;

        struct s2n_stuffer input = { 0 };
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&input, 0));
        EXPECT_SUCCESS(s2n_connection_set_io_stuffers(&input, NULL, conn));

        for (int i = 0; i < valid_tls12_handshakes_size; i++) {
            int handshake = valid_tls12_handshakes[i];

            conn->handshake.handshake_type = handshake;

            for (int j = 1; j < S2N_MAX_HANDSHAKE_LENGTH; j++) {
                EXPECT_SUCCESS(s2n_setup_handler_to_expect(CLIENT_CHANGE_CIPHER_SPEC, S2N_SERVER));
                conn->handshake.message_number = j;
                conn->in_status = ENCRYPTED;

                EXPECT_SUCCESS(s2n_test_write_header(&input, TLS_CHANGE_CIPHER_SPEC, 0));

                if (handshakes[handshake][j] == CLIENT_CHANGE_CIPHER_SPEC) {
                    EXPECT_SUCCESS(s2n_handshake_read_io(conn));
                    EXPECT_TRUE(expected_handler_called);
                    EXPECT_FALSE(unexpected_handler_called);
                } else {
                    EXPECT_FAILURE_WITH_ERRNO(s2n_handshake_read_io(conn), S2N_ERR_BAD_MESSAGE);
                    EXPECT_FALSE(expected_handler_called);
                    EXPECT_FALSE(unexpected_handler_called);
                }

                EXPECT_SUCCESS(s2n_stuffer_wipe(&input));
            }
        }

        EXPECT_SUCCESS(s2n_stuffer_free(&input));
        EXPECT_SUCCESS(s2n_connection_free(conn));
    };

    /* Test: TLS1.2 client can receive a hello request message at any time. */
    {
        struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT);
        conn->actual_protocol_version = S2N_TLS12;

        struct s2n_stuffer input = { 0 };
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&input, 0));
        EXPECT_SUCCESS(s2n_connection_set_io_stuffers(&input, NULL, conn));

        for (size_t i = 0; i < valid_tls12_handshakes_size; i++) {
            uint16_t handshake = valid_tls12_handshakes[i];

            for (size_t j = 0; j < S2N_MAX_HANDSHAKE_LENGTH; j++) {
                if (handshakes[handshake][j] == APPLICATION_DATA) {
                    break;
                }

                conn->handshake.message_number = j;
                conn->in_status = ENCRYPTED;
                conn->handshake.handshake_type = handshake;

                EXPECT_SUCCESS(s2n_test_write_header(&input, TLS_HANDSHAKE, TLS_HELLO_REQUEST));
                EXPECT_SUCCESS(s2n_handshake_read_io(conn));
                EXPECT_EQUAL(conn->handshake.message_number, j);

                EXPECT_SUCCESS(s2n_stuffer_wipe(&input));
            }
        }

        EXPECT_FALSE(unexpected_handler_called);
        EXPECT_SUCCESS(s2n_stuffer_free(&input));
        EXPECT_SUCCESS(s2n_connection_free(conn));
    };

    /* Test: TLS1.2 s2n_handshake_read_io should accept only the expected message */
    {
        /* TLS1.2 should accept the expected message */
        {
            struct s2n_connection *conn = s2n_connection_new(S2N_SERVER);
            conn->actual_protocol_version = S2N_TLS12;

            struct s2n_stuffer input = { 0 };
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&input, 0));
            EXPECT_SUCCESS(s2n_connection_set_io_stuffers(&input, NULL, conn));

            conn->handshake.handshake_type = 0;
            conn->handshake.message_number = 0;
            EXPECT_EQUAL(ACTIVE_MESSAGE(conn), CLIENT_HELLO);
            EXPECT_SUCCESS(s2n_setup_handler_to_expect(CLIENT_HELLO, S2N_SERVER));

            EXPECT_SUCCESS(s2n_test_write_header(&input, TLS_HANDSHAKE, TLS_CLIENT_HELLO));
            EXPECT_SUCCESS(s2n_handshake_read_io(conn));

            EXPECT_EQUAL(conn->handshake.message_number, 1);
            EXPECT_FALSE(unexpected_handler_called);
            EXPECT_TRUE(expected_handler_called);

            EXPECT_SUCCESS(s2n_stuffer_free(&input));
            EXPECT_SUCCESS(s2n_connection_free(conn));
        };

        /* TLS1.2 should error for an unexpected message */
        {
            struct s2n_connection *conn = s2n_connection_new(S2N_SERVER);
            conn->actual_protocol_version = S2N_TLS12;

            struct s2n_stuffer input = { 0 };
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&input, 0));
            EXPECT_SUCCESS(s2n_connection_set_io_stuffers(&input, NULL, conn));

            conn->handshake.handshake_type = 0;
            conn->handshake.message_number = 0;
            EXPECT_EQUAL(ACTIVE_MESSAGE(conn), CLIENT_HELLO);
            EXPECT_SUCCESS(s2n_setup_handler_to_expect(CLIENT_HELLO, S2N_SERVER));

            EXPECT_SUCCESS(s2n_test_write_header(&input, TLS_HANDSHAKE, TLS_CERTIFICATE));
            EXPECT_FAILURE_WITH_ERRNO(s2n_handshake_read_io(conn), S2N_ERR_BAD_MESSAGE);

            EXPECT_EQUAL(conn->handshake.message_number, 0);
            EXPECT_FALSE(unexpected_handler_called);
            EXPECT_FALSE(expected_handler_called);

            EXPECT_SUCCESS(s2n_stuffer_free(&input));
            EXPECT_SUCCESS(s2n_connection_free(conn));
        };

        /* TLS1.2 should error for an expected message from the wrong writer */
        {
            struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT);
            conn->actual_protocol_version = S2N_TLS12;

            struct s2n_stuffer input = { 0 };
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&input, 0));
            EXPECT_SUCCESS(s2n_connection_set_io_stuffers(&input, NULL, conn));

            conn->handshake.handshake_type = 0;
            conn->handshake.message_number = 0;
            EXPECT_EQUAL(ACTIVE_MESSAGE(conn), CLIENT_HELLO);
            EXPECT_SUCCESS(s2n_setup_handler_to_expect(CLIENT_HELLO, S2N_SERVER));

            EXPECT_SUCCESS(s2n_test_write_header(&input, TLS_HANDSHAKE, TLS_CLIENT_HELLO));
            EXPECT_FAILURE_WITH_ERRNO(s2n_handshake_read_io(conn), S2N_ERR_BAD_MESSAGE);

            EXPECT_EQUAL(conn->handshake.message_number, 0);
            EXPECT_FALSE(unexpected_handler_called);
            EXPECT_FALSE(expected_handler_called);

            EXPECT_SUCCESS(s2n_stuffer_free(&input));
            EXPECT_SUCCESS(s2n_connection_free(conn));
        };

        /* TLS1.2 should error for an expected message from the wrong record type */
        {
            /* Unfortunately, all our non-handshake record types have a message type of 0,
             * and the combination of TLS_HANDSHAKE + "0" is actually a message (TLS_HELLO_REQUEST)
             * which can appear at any point in a TLS1.2 handshake.
             *
             * To test, temporarily modify the actions table.
             * We MUST restore this after this test.
             */
            uint8_t old_message_type = state_machine[SERVER_CHANGE_CIPHER_SPEC].message_type;
            state_machine[SERVER_CHANGE_CIPHER_SPEC].message_type = 1;

            struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT);
            conn->actual_protocol_version = S2N_TLS12;

            struct s2n_stuffer input = { 0 };
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&input, 0));
            EXPECT_SUCCESS(s2n_connection_set_io_stuffers(&input, NULL, conn));

            uint8_t server_css_message_number = 2;
            conn->handshake.handshake_type = NEGOTIATED;
            conn->handshake.message_number = server_css_message_number;
            EXPECT_EQUAL(ACTIVE_MESSAGE(conn), SERVER_CHANGE_CIPHER_SPEC);
            EXPECT_SUCCESS(s2n_setup_handler_to_expect(SERVER_CHANGE_CIPHER_SPEC, S2N_CLIENT));

            EXPECT_SUCCESS(s2n_test_write_header(&input, TLS_HANDSHAKE, ACTIVE_STATE(conn).message_type));
            EXPECT_FAILURE_WITH_ERRNO(s2n_handshake_read_io(conn), S2N_ERR_BAD_MESSAGE);

            EXPECT_EQUAL(conn->handshake.message_number, server_css_message_number);
            EXPECT_FALSE(unexpected_handler_called);
            EXPECT_FALSE(expected_handler_called);

            EXPECT_SUCCESS(s2n_stuffer_free(&input));
            EXPECT_SUCCESS(s2n_connection_free(conn));
            state_machine[SERVER_CHANGE_CIPHER_SPEC].message_type = old_message_type;
        };
    };

    /* Test: TLS1.2 handshake type name maximum size is set correctly.
     * The maximum size is the size of a name with all flags set. */
    {
        size_t correct_size = 0;
        for (size_t i = 0; i < s2n_array_len(tls12_handshake_type_names); i++) {
            correct_size += strlen(tls12_handshake_type_names[i]);
        }
        if (correct_size > MAX_HANDSHAKE_TYPE_LEN) {
            fprintf(stderr, "\nMAX_HANDSHAKE_TYPE_LEN should be at least %lu\n", (unsigned long) correct_size);
            FAIL_MSG("MAX_HANDSHAKE_TYPE_LEN wrong for TLS1.2 handshakes");
        }
    };

    /* Test: TLS 1.2 handshake types are all properly printed */
    {
        struct s2n_connection *conn = s2n_connection_new(S2N_SERVER);
        conn->actual_protocol_version = S2N_TLS12;

        conn->handshake.handshake_type = INITIAL;
        EXPECT_STRING_EQUAL("INITIAL", s2n_connection_get_handshake_type_name(conn));

        conn->handshake.handshake_type = NEGOTIATED | FULL_HANDSHAKE;
        EXPECT_STRING_EQUAL("NEGOTIATED|FULL_HANDSHAKE", s2n_connection_get_handshake_type_name(conn));

        const char *all_flags_handshake_type_name = "NEGOTIATED|FULL_HANDSHAKE|CLIENT_AUTH|NO_CLIENT_CERT|"
                                                    "TLS12_PERFECT_FORWARD_SECRECY|OCSP_STATUS|WITH_SESSION_TICKET|WITH_NPN";
        conn->handshake.handshake_type = NEGOTIATED | FULL_HANDSHAKE | CLIENT_AUTH | NO_CLIENT_CERT | TLS12_PERFECT_FORWARD_SECRECY | OCSP_STATUS | WITH_SESSION_TICKET | WITH_NPN;
        EXPECT_STRING_EQUAL(all_flags_handshake_type_name, s2n_connection_get_handshake_type_name(conn));

        const char *handshake_type_name;
        for (int i = 0; i < valid_tls12_handshakes_size; i++) {
            conn->handshake.handshake_type = valid_tls12_handshakes[i];

            handshake_type_name = s2n_connection_get_handshake_type_name(conn);

            /* The handshake type names must be unique */
            for (int j = 0; j < valid_tls12_handshakes_size; j++) {
                conn->handshake.handshake_type = valid_tls12_handshakes[j];
                if (i == j) {
                    EXPECT_STRING_EQUAL(handshake_type_name, s2n_connection_get_handshake_type_name(conn));
                } else {
                    EXPECT_STRING_NOT_EQUAL(handshake_type_name, s2n_connection_get_handshake_type_name(conn));
                }
            }
        }

        EXPECT_SUCCESS(s2n_connection_free(conn));
    };

    /* Test: TLS 1.2 message types are all properly printed */
    {
        uint32_t test_handshake_type = NEGOTIATED | FULL_HANDSHAKE | TLS12_PERFECT_FORWARD_SECRECY | OCSP_STATUS | CLIENT_AUTH | WITH_SESSION_TICKET | WITH_NPN;
        const char *expected[] = { "CLIENT_HELLO",
            "SERVER_HELLO", "SERVER_CERT", "SERVER_CERT_STATUS", "SERVER_KEY", "SERVER_CERT_REQ", "SERVER_HELLO_DONE",
            "CLIENT_CERT", "CLIENT_KEY", "CLIENT_CERT_VERIFY", "CLIENT_CHANGE_CIPHER_SPEC", "CLIENT_NPN",
            "CLIENT_FINISHED", "SERVER_NEW_SESSION_TICKET", "SERVER_CHANGE_CIPHER_SPEC", "SERVER_FINISHED",
            "APPLICATION_DATA" };

        struct s2n_connection *conn = s2n_connection_new(S2N_SERVER);

        conn->handshake.handshake_type = test_handshake_type;

        for (size_t i = 0; i < sizeof(expected) / sizeof(char *); i++) {
            conn->handshake.message_number = i;
            EXPECT_STRING_EQUAL(expected[i], s2n_connection_get_last_message_name(conn));
        }

        EXPECT_SUCCESS(s2n_connection_free(conn));
    };

    /* Test: A WITH_NPN form of every valid, negotiated handshake exists */
    {
        uint32_t handshake_type_original, handshake_type_npn;
        message_type_t *messages_original, *messages_npn;

        for (size_t i = 0; i < valid_tls12_handshakes_size; i++) {
            handshake_type_original = valid_tls12_handshakes[i];
            messages_original = handshakes[handshake_type_original];

            /* Ignore INITIAL and WITH_NPN handshakes */
            if (!(handshake_type_original & NEGOTIATED) || (handshake_type_original & WITH_NPN)) {
                continue;
            }

            /* Get the WITH_NPN form of the handshake */
            handshake_type_npn = handshake_type_original | WITH_NPN;
            messages_npn = handshakes[handshake_type_npn];

            for (size_t j = 0, j_npn = 0; j < S2N_MAX_HANDSHAKE_LENGTH && j_npn < S2N_MAX_HANDSHAKE_LENGTH; j++, j_npn++) {
                /* The original handshake cannot contain the Next Protocol message */
                EXPECT_NOT_EQUAL(messages_original[j], CLIENT_NPN);

                /* Skip the Next Protocol message in WITH_NPN handshake */
                if (messages_npn[j_npn] == CLIENT_NPN) {
                    j_npn++;
                }

                /* Otherwise the handshakes must be equivalent */
                EXPECT_EQUAL(messages_original[j], messages_npn[j_npn]);
            }
        }
    };

    END_TEST();
    return 0;
}
