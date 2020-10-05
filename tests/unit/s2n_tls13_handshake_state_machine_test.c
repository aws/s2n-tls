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

#include "s2n_test.h"

#include "testlib/s2n_testlib.h"

#include <stdint.h>
#include <stdlib.h>

#include <s2n.h>

#include "crypto/s2n_fips.h"

#include "tls/s2n_cipher_suites.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_handshake.h"
#include "tls/s2n_quic_support.h"
#include "tls/s2n_tls13.h"

/* Just to get access to the static functions / variables we need to test */
#include "tls/s2n_handshake_io.c"

static message_type_t invalid_handshake[S2N_MAX_HANDSHAKE_LENGTH] = { 0 };

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
    for (int i = 0; i < s2n_array_len(tls13_state_machine); i++) {
        tls13_state_machine[i].handler[0] = s2n_test_handler;
        tls13_state_machine[i].handler[1] = s2n_test_handler;
    }

    tls13_state_machine[expected].handler[direction] = s2n_test_expected_handler;

    expected_handler_called = 0;
    unexpected_handler_called = 0;

    return 0;
}

static int s2n_test_write_header(struct s2n_stuffer *output, uint8_t record_type, uint8_t message_type)
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

    EXPECT_SUCCESS(s2n_enable_tls13());

    /* Construct an array of all valid tls1.3 handshake_types */
    uint16_t valid_tls13_handshakes[S2N_HANDSHAKES_COUNT];
    int valid_tls13_handshakes_size = 0;
    for (int i = 0; i < S2N_HANDSHAKES_COUNT; i++) {
        if(memcmp(tls13_handshakes[i], invalid_handshake, S2N_MAX_HANDSHAKE_LENGTH) != 0) {
            valid_tls13_handshakes[valid_tls13_handshakes_size] = i;
            valid_tls13_handshakes_size++;
        }
    }
    EXPECT_TRUE(valid_tls13_handshakes_size > 0);
    EXPECT_TRUE(valid_tls13_handshakes_size < S2N_HANDSHAKES_COUNT);

    /* Use handler stubs to avoid errors in handler implementation */
    for (int i = 0; i < s2n_array_len(tls13_state_machine); i++) {
        tls13_state_machine[i].handler[0] = s2n_test_handler;
        tls13_state_machine[i].handler[1] = s2n_test_handler;
    }

    /* Test: A MIDDLEBOX_COMPAT form of every valid, negotiated handshake exists
     *       and matches the non-MIDDLEBOX_COMPAT form EXCEPT for CCS messages */
    {
        uint32_t handshake_type_original, handshake_type_mc;
        message_type_t *messages_original, *messages_mc;

        for (size_t i = 0; i < valid_tls13_handshakes_size; i++) {

            handshake_type_original = valid_tls13_handshakes[i];
            messages_original = tls13_handshakes[handshake_type_original];

            /* Ignore INITIAL and MIDDLEBOX_COMPAT handshakes */
            if (!IS_NEGOTIATED(handshake_type_original) || IS_MIDDLEBOX_COMPAT_MODE(handshake_type_original)) {
                continue;
            }

            /* MIDDLEBOX_COMPAT form of the handshake */
            handshake_type_mc = handshake_type_original | MIDDLEBOX_COMPAT;
            messages_mc = tls13_handshakes[handshake_type_mc];

            for (size_t j = 0, j_mc = 0; j < S2N_MAX_HANDSHAKE_LENGTH && j_mc < S2N_MAX_HANDSHAKE_LENGTH; j++, j_mc++) {
                /* The original handshake cannot contain CCS messages */
                EXPECT_NOT_EQUAL(messages_original[j], SERVER_CHANGE_CIPHER_SPEC);
                EXPECT_NOT_EQUAL(messages_original[j], CLIENT_CHANGE_CIPHER_SPEC);

                /* Skip CCS messages in the MIDDLEBOX_COMPAT handshake */
                while (messages_mc[j_mc] == SERVER_CHANGE_CIPHER_SPEC ||
                        messages_mc[j_mc] == CLIENT_CHANGE_CIPHER_SPEC) {
                    j_mc++;
                }

                /* The handshakes must be otherwise equivalent */
                EXPECT_EQUAL(messages_original[j], messages_mc[j_mc]);
            }
        }
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
                if (tls13_handshakes[handshake][j] == CLIENT_CHANGE_CIPHER_SPEC) {
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
                if (tls13_handshakes[handshake][j] == SERVER_CHANGE_CIPHER_SPEC) {
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
                if (tls13_handshakes[handshake][j] == SERVER_CHANGE_CIPHER_SPEC) {
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
                if (tls13_handshakes[handshake][j] == CLIENT_CHANGE_CIPHER_SPEC) {
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

        EXPECT_SUCCESS(s2n_setup_handler_to_expect(SERVER_CHANGE_CIPHER_SPEC, S2N_CLIENT));

        for (int i = 0; i < valid_tls13_handshakes_size; i++) {
            int handshake = valid_tls13_handshakes[i];

            conn->handshake.handshake_type = handshake;
            conn->in_status = ENCRYPTED;

            for (int j = 1; j < S2N_MAX_HANDSHAKE_LENGTH; j++) {
                conn->handshake.message_number = j;

                EXPECT_SUCCESS(s2n_test_write_header(&input, TLS_CHANGE_CIPHER_SPEC, 0));

                EXPECT_SUCCESS(s2n_handshake_read_io(conn));

                if (tls13_handshakes[handshake][j] == SERVER_CHANGE_CIPHER_SPEC) {
                    EXPECT_EQUAL(conn->handshake.message_number, j + 1);
                } else {
                    EXPECT_EQUAL(conn->handshake.message_number, j);
                }

                EXPECT_FALSE(unexpected_handler_called);
                EXPECT_TRUE(expected_handler_called);

                EXPECT_SUCCESS(s2n_stuffer_wipe(&input));
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

        EXPECT_SUCCESS(s2n_setup_handler_to_expect(CLIENT_CHANGE_CIPHER_SPEC, S2N_SERVER));

        for (int i = 0; i < valid_tls13_handshakes_size; i++) {
            int handshake = valid_tls13_handshakes[i];

            conn->handshake.handshake_type = handshake;
            conn->in_status = ENCRYPTED;

            for (int j = 1; j < S2N_MAX_HANDSHAKE_LENGTH; j++) {
                conn->handshake.message_number = j;

                EXPECT_SUCCESS(s2n_test_write_header(&input, TLS_CHANGE_CIPHER_SPEC, 0));

                EXPECT_SUCCESS(s2n_handshake_read_io(conn));

                if (tls13_handshakes[handshake][j] == CLIENT_CHANGE_CIPHER_SPEC) {
                    EXPECT_EQUAL(conn->handshake.message_number, j + 1);
                } else {
                    EXPECT_EQUAL(conn->handshake.message_number, j);
                }

                EXPECT_FALSE(unexpected_handler_called);
                EXPECT_TRUE(expected_handler_called);

                EXPECT_SUCCESS(s2n_stuffer_wipe(&input));
            }
        }

        EXPECT_SUCCESS(s2n_stuffer_free(&input));
        EXPECT_SUCCESS(s2n_connection_free(conn));
    }

    /* Test: TLS1.3 s2n_handshake_read_io should accept only the expected message */
    {
        /* TLS1.3 should accept the expected message */
        {
            struct s2n_connection *conn = s2n_connection_new(S2N_SERVER);
            conn->actual_protocol_version = S2N_TLS13;

            struct s2n_stuffer input;
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
        }

        /* TLS1.3 should error for an unexpected message */
        {
            struct s2n_connection *conn = s2n_connection_new(S2N_SERVER);
            conn->actual_protocol_version = S2N_TLS13;

            struct s2n_stuffer input;
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
        }

        /* TLS1.3 should error for an expected message from the wrong writer */
        {
            struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT);
            conn->actual_protocol_version = S2N_TLS13;

            struct s2n_stuffer input;
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
        }

        /* TLS1.3 should error for an expected message from the wrong record type */
        {
            struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT);
            conn->actual_protocol_version = S2N_TLS13;

            struct s2n_stuffer input;
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&input, 0));
            EXPECT_SUCCESS(s2n_connection_set_io_stuffers(&input, NULL, conn));

            uint8_t server_css_message_number = 2;
            conn->handshake.handshake_type = NEGOTIATED | FULL_HANDSHAKE | MIDDLEBOX_COMPAT;
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
        }
    }

    /* Test: TLS 1.3 MIDDLEBOX_COMPAT handshakes all follow CCS middlebox compatibility rules.
     * RFC: https://tools.ietf.org/html/rfc8446#appendix-D.4 */
    {
        bool change_cipher_spec_found;
        uint32_t handshake_type;
        message_type_t *messages;

        /* Test: "If not offering early data, the client sends a dummy change_cipher_spec record immediately before
         *       its second flight. This may either be before its second ClientHello or before its encrypted handshake flight." */
        for (size_t i = 0; i < valid_tls13_handshakes_size; i++) {
            change_cipher_spec_found = false;
            handshake_type = valid_tls13_handshakes[i];
            messages = tls13_handshakes[handshake_type];

            /* Ignore INITIAL and non-MIDDLEBOX_COMPAT handshakes */
            if (!IS_NEGOTIATED(handshake_type) || !IS_MIDDLEBOX_COMPAT_MODE(handshake_type)) {
                continue;
            }

            for (size_t j = 1; j < S2N_MAX_HANDSHAKE_LENGTH; j++) {

                /* Is it the second client flight?
                 * Have we switched from the server sending to the client sending? */
                if (tls13_state_machine[messages[j]].writer != 'C'
                        || tls13_state_machine[messages[j - 1]].writer != 'S') {
                    continue;
                }

                EXPECT_EQUAL(messages[j], CLIENT_CHANGE_CIPHER_SPEC);
                EXPECT_EQUAL(tls13_state_machine[messages[j + 1]].writer, 'C');

                /* CCS message found. We are done with this handshake. */
                change_cipher_spec_found = true;
                break;
            }

            EXPECT_TRUE(change_cipher_spec_found);
        }

        /* Test: "If offering early data, the [change_cipher_spec] record is placed immediately after the first ClientHello."
         *
         * TODO: This can't be tested yet because S2N doesn't support early data. */

        /* Test: "The server sends a dummy change_cipher_spec record immediately after its first handshake message.
         *       This may either be after a ServerHello or a HelloRetryRequest." */
        for (size_t i = 0; i < valid_tls13_handshakes_size; i++) {
            change_cipher_spec_found = false;
            handshake_type = valid_tls13_handshakes[i];
            messages = tls13_handshakes[handshake_type];

            /* Ignore INITIAL and non-MIDDLEBOX_COMPAT handshakes */
            if (!IS_NEGOTIATED(handshake_type) || !IS_MIDDLEBOX_COMPAT_MODE(handshake_type)) {
                continue;
            }

            for (size_t j = 1; j < S2N_MAX_HANDSHAKE_LENGTH; j++) {

                /* Is it the first server flight?
                 * Have we switched from the client sending to the server sending? */
                if (tls13_state_machine[messages[j]].writer != 'S'
                        || tls13_state_machine[messages[j-1]].writer != 'C') {
                    continue;
                }

                EXPECT_EQUAL(messages[j + 1], SERVER_CHANGE_CIPHER_SPEC);
                EXPECT_TRUE(messages[j] == SERVER_HELLO || messages[j] == HELLO_RETRY_MSG);

                /* CCS message found. We are done with this handshake. */
                change_cipher_spec_found = true;
                break;
            }

            EXPECT_TRUE(change_cipher_spec_found);
        }
    }

    /* Test: TLS1.3 s2n_conn_set_handshake_type sets only handshake flags allowed by TLS1.3 */
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

        /* Verify that tls1.2 DOES set the flags allowed by tls1.2 */
        conn->actual_protocol_version = S2N_TLS12;
        EXPECT_SUCCESS(s2n_conn_set_handshake_type(conn));
        EXPECT_TRUE(conn->handshake.handshake_type & TLS12_PERFECT_FORWARD_SECRECY );
        EXPECT_TRUE(conn->handshake.handshake_type & OCSP_STATUS );
        EXPECT_TRUE(conn->handshake.handshake_type & WITH_SESSION_TICKET );
        EXPECT_TRUE(conn->handshake.handshake_type & CLIENT_AUTH );

        /* Verify that tls1.2 DOES NOT set the flags only allowed by tls1.3 */
        EXPECT_FALSE(conn->handshake.handshake_type & MIDDLEBOX_COMPAT);
        EXPECT_FALSE(conn->handshake.handshake_type & HELLO_RETRY_REQUEST);

        /* Verify that tls1.3 ONLY sets the flags allowed by tls1.3 */
        conn->actual_protocol_version = S2N_TLS13;
        EXPECT_SUCCESS(s2n_conn_set_handshake_type(conn));
        EXPECT_EQUAL(conn->handshake.handshake_type, NEGOTIATED | FULL_HANDSHAKE | CLIENT_AUTH | MIDDLEBOX_COMPAT);

        EXPECT_SUCCESS(s2n_connection_free(conn));
    }

    /* Test: s2n_conn_set_handshake_type only allows HELLO_RETRY_REQUEST with TLS1.3 */
    {
        struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT);

        /* HELLO_RETRY_REQUEST allowed with tls1.3 */
        conn->actual_protocol_version = S2N_TLS13;
        conn->handshake.handshake_type = INITIAL | HELLO_RETRY_REQUEST;
        EXPECT_SUCCESS(s2n_conn_set_handshake_type(conn));
        EXPECT_TRUE(conn->handshake.handshake_type & HELLO_RETRY_REQUEST);

        /* HELLO_RETRY_REQUEST not allowed with tls1.2 */
        conn->actual_protocol_version = S2N_TLS12;
        conn->handshake.handshake_type = INITIAL | HELLO_RETRY_REQUEST;
        EXPECT_FAILURE_WITH_ERRNO(s2n_conn_set_handshake_type(conn), S2N_ERR_INVALID_HELLO_RETRY);

        EXPECT_SUCCESS(s2n_connection_free(conn));
    }

    /* Test: TLS1.3 handshake type name maximum size is set correctly.
     *       The maximum size is the size of a name with all flags set. */
    {
        size_t correct_size = 0;
        for (size_t i = 0; i < s2n_array_len(handshake_type_names); i++) {
            correct_size += strlen(handshake_type_names[i]);
        }
        EXPECT_EQUAL(correct_size, MAX_HANDSHAKE_TYPE_LEN);
    }

    /* Test: TLS 1.3 handshake types are all properly printed */
    {
        struct s2n_connection *conn = s2n_connection_new(S2N_SERVER);
        conn->actual_protocol_version = S2N_TLS13;

        conn->handshake.handshake_type = INITIAL;
        EXPECT_STRING_EQUAL("INITIAL", s2n_connection_get_handshake_type_name(conn));

        conn->handshake.handshake_type = NEGOTIATED | FULL_HANDSHAKE;
        EXPECT_STRING_EQUAL("NEGOTIATED|FULL_HANDSHAKE", s2n_connection_get_handshake_type_name(conn));

        conn->handshake.handshake_type = NEGOTIATED | FULL_HANDSHAKE | HELLO_RETRY_REQUEST;
        EXPECT_STRING_EQUAL("NEGOTIATED|FULL_HANDSHAKE|HELLO_RETRY_REQUEST", s2n_connection_get_handshake_type_name(conn));

        const char* all_flags_handshake_type_name = "NEGOTIATED|FULL_HANDSHAKE|CLIENT_AUTH|WITH_SESSION_TICKET|"
                "NO_CLIENT_CERT|MIDDLEBOX_COMPAT";
        conn->handshake.handshake_type = NEGOTIATED | FULL_HANDSHAKE | CLIENT_AUTH | WITH_SESSION_TICKET |
                NO_CLIENT_CERT | MIDDLEBOX_COMPAT;
        EXPECT_STRING_EQUAL(all_flags_handshake_type_name, s2n_connection_get_handshake_type_name(conn));

        const char *handshake_type_name;
        for (int i = 0; i < valid_tls13_handshakes_size; i++) {
            conn->handshake.handshake_type = i;

            handshake_type_name = s2n_connection_get_handshake_type_name(conn);

            /* The handshake type names must be unique */
            for (int j = 0; j < valid_tls13_handshakes_size; j++) {
                conn->handshake.handshake_type = j;
                if (i == j) {
                    EXPECT_STRING_EQUAL(handshake_type_name, s2n_connection_get_handshake_type_name(conn));
                } else {
                    EXPECT_STRING_NOT_EQUAL(handshake_type_name, s2n_connection_get_handshake_type_name(conn));
                }
            }
        }

        EXPECT_SUCCESS(s2n_connection_free(conn));
    }

    /* Test: TLS 1.3 message types are all properly printed */
    {
        uint32_t test_handshake_type = NEGOTIATED | FULL_HANDSHAKE | MIDDLEBOX_COMPAT;
        const char* expected[] = { "CLIENT_HELLO", "SERVER_HELLO", "SERVER_CHANGE_CIPHER_SPEC",
                "ENCRYPTED_EXTENSIONS", "SERVER_CERT", "SERVER_CERT_VERIFY", "SERVER_FINISHED",
                "CLIENT_CHANGE_CIPHER_SPEC", "CLIENT_FINISHED", "APPLICATION_DATA" };

        struct s2n_connection *conn = s2n_connection_new(S2N_SERVER);
        conn->actual_protocol_version = S2N_TLS13;

        conn->handshake.handshake_type = test_handshake_type;

        for (int i = 0; i < s2n_array_len(expected); i++) {
            conn->handshake.message_number = i;
            EXPECT_STRING_EQUAL(expected[i], s2n_connection_get_last_message_name(conn));
        }

        EXPECT_SUCCESS(s2n_connection_free(conn));
    }

    /* Test: TLS 1.3 message types are all properly printed for client auth */
    {
        uint32_t test_handshake_type = NEGOTIATED | FULL_HANDSHAKE | CLIENT_AUTH;
        const char* expected[] = { "CLIENT_HELLO",
            "SERVER_HELLO", "ENCRYPTED_EXTENSIONS", "SERVER_CERT_REQ", "SERVER_CERT", "SERVER_CERT_VERIFY", "SERVER_FINISHED",
            "CLIENT_CERT", "CLIENT_CERT_VERIFY", "CLIENT_FINISHED",
            "APPLICATION_DATA" };

        struct s2n_connection *conn = s2n_connection_new(S2N_SERVER);
        conn->actual_protocol_version = S2N_TLS13;

        conn->handshake.handshake_type = test_handshake_type;

        for (int i = 0; i < s2n_array_len(expected); i++) {
            conn->handshake.message_number = i;
            EXPECT_STRING_EQUAL(expected[i], s2n_connection_get_last_message_name(conn));
        }

        EXPECT_SUCCESS(s2n_connection_free(conn));
    }

    /* Test: Make sure not to miss out populating any message names */
    {
        for (int i = CLIENT_HELLO; i <= APPLICATION_DATA; i++) {
            EXPECT_NOT_NULL(message_names[i]);
        }
    }

    END_TEST();
    return 0;
}
