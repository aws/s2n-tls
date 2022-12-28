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
#include "stuffer/s2n_stuffer.h"
#include "testlib/s2n_testlib.h"
#include "tls/s2n_tls.h"
#include "utils/s2n_safety.h"

S2N_RESULT s2n_calculate_padding(uint8_t protocol_len, uint8_t *padding_len);
S2N_RESULT s2n_write_npn_protocol(struct s2n_connection *conn, struct s2n_stuffer *out);
S2N_RESULT s2n_read_npn_protocol(struct s2n_connection *conn, struct s2n_stuffer *in);

int main(int argc, char **argv)
{
    BEGIN_TEST();

    const char *protocols[] = { "http/1.1", "spdy/1", "spdy/2" };

    /* Test s2n_next_protocol_send */
    {
        /* Safety checks */
        EXPECT_FAILURE(s2n_next_protocol_send(NULL));

        /* Should fail for >= TLS1.3 */
        {
            DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT), s2n_connection_ptr_free);
            EXPECT_NOT_NULL(client_conn);

            /* Fails for TLS1.3 */
            client_conn->actual_protocol_version = S2N_TLS13;
            EXPECT_FAILURE_WITH_ERRNO(s2n_next_protocol_send(client_conn), S2N_ERR_BAD_MESSAGE);

            /* Succeeds for TLS1.2 */
            client_conn->actual_protocol_version = S2N_TLS12;
            EXPECT_SUCCESS(s2n_next_protocol_send(client_conn));
        };
    };

    /* Test s2n_next_protocol_recv */
    {
        /* Safety checks */
        EXPECT_FAILURE(s2n_next_protocol_recv(NULL));

        /* Should parse s2n_next_protocol_send */
        {
            DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER), s2n_connection_ptr_free);
            EXPECT_NOT_NULL(server_conn);
            DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT), s2n_connection_ptr_free);
            EXPECT_NOT_NULL(client_conn);

            client_conn->actual_protocol_version = S2N_TLS12;

            char protocol[] = { "http/1.1" };
            uint8_t protocol_len = strlen(protocol);
            EXPECT_MEMCPY_SUCCESS(client_conn->application_protocol, protocol, protocol_len + 1);

            struct s2n_stuffer *stuffer = &client_conn->handshake.io;

            EXPECT_SUCCESS(s2n_next_protocol_send(client_conn));
            EXPECT_SUCCESS(s2n_stuffer_copy(stuffer, &server_conn->handshake.io, s2n_stuffer_data_available(stuffer)));

            /* Fails for TLS1.3 */
            server_conn->actual_protocol_version = S2N_TLS13;
            EXPECT_FAILURE_WITH_ERRNO(s2n_next_protocol_recv(server_conn), S2N_ERR_BAD_MESSAGE);

            /* Succeeds for TLS1.2 */
            server_conn->actual_protocol_version = S2N_TLS12;
            EXPECT_SUCCESS(s2n_next_protocol_recv(server_conn));
            EXPECT_EQUAL(s2n_stuffer_data_available(&server_conn->handshake.io), 0);

            EXPECT_BYTEARRAY_EQUAL(client_conn->application_protocol, server_conn->application_protocol, protocol_len);
        };
    };

    /* s2n_write_npn_protocol */
    {
        DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT), s2n_connection_ptr_free);
        EXPECT_NOT_NULL(client_conn);

        uint8_t first_protocol_len = strlen(protocols[0]);
        EXPECT_MEMCPY_SUCCESS(client_conn->application_protocol, protocols[0], first_protocol_len + 1);

        DEFER_CLEANUP(struct s2n_stuffer out = { 0 }, s2n_stuffer_free);
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&out, 0));
        EXPECT_OK(s2n_write_npn_protocol(client_conn, &out));

        uint8_t protocol_len = 0;
        EXPECT_SUCCESS(s2n_stuffer_read_uint8(&out, &protocol_len));

        uint8_t protocol[UINT8_MAX] = { 0 };
        EXPECT_SUCCESS(s2n_stuffer_read_bytes(&out, protocol, protocol_len));
        EXPECT_BYTEARRAY_EQUAL(protocol, protocols[0], protocol_len);

        uint8_t padding_len = 0;
        EXPECT_SUCCESS(s2n_stuffer_read_uint8(&out, &padding_len));
        EXPECT_TRUE(padding_len > 0);

        for (size_t i = 0; i < padding_len; i++) {
            uint8_t byte = UINT8_MAX;
            EXPECT_SUCCESS(s2n_stuffer_read_uint8(&out, &byte));
            EXPECT_EQUAL(byte, 0);
        }
        EXPECT_EQUAL(s2n_stuffer_data_available(&out), 0);
    };

    /* s2n_read_npn_protocol can parse s2n_write_npn_protocol */
    {
        DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT), s2n_connection_ptr_free);
        EXPECT_NOT_NULL(client_conn);

        DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER), s2n_connection_ptr_free);
        EXPECT_NOT_NULL(server_conn);

        uint8_t first_protocol_len = strlen(protocols[0]);
        EXPECT_MEMCPY_SUCCESS(client_conn->application_protocol, protocols[0], first_protocol_len + 1);

        DEFER_CLEANUP(struct s2n_stuffer out = { 0 }, s2n_stuffer_free);
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&out, 0));
        EXPECT_OK(s2n_write_npn_protocol(client_conn, &out));
        EXPECT_OK(s2n_read_npn_protocol(server_conn, &out));

        EXPECT_NOT_NULL(s2n_get_application_protocol(server_conn));
        EXPECT_BYTEARRAY_EQUAL(s2n_get_application_protocol(server_conn), protocols[0], strlen(protocols[0]));
    };

    /* s2n_read_npn_protocol can read empty message */
    {
        DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER), s2n_connection_ptr_free);
        EXPECT_NOT_NULL(server_conn);

        DEFER_CLEANUP(struct s2n_stuffer out = { 0 }, s2n_stuffer_free);
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&out, 0));

        /* Zero-length protocol */
        EXPECT_SUCCESS(s2n_stuffer_write_uint8(&out, 0));
        uint8_t padding_len = 0;
        EXPECT_OK(s2n_calculate_padding(0, &padding_len));
        EXPECT_SUCCESS(s2n_stuffer_write_uint8(&out, padding_len));
        for (size_t i = 0; i < padding_len; i++) {
            EXPECT_SUCCESS(s2n_stuffer_write_uint8(&out, 0));
        }

        EXPECT_OK(s2n_read_npn_protocol(server_conn, &out));
        EXPECT_NULL(s2n_get_application_protocol(server_conn));
    };

    /* s2n_read_npn_protocol errors on malformed message */
    {
        DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER), s2n_connection_ptr_free);
        EXPECT_NOT_NULL(server_conn);

        uint8_t wire_bytes[] = {
            /* Incorrect length of protocol */
            0x10,
        };

        DEFER_CLEANUP(struct s2n_stuffer out = { 0 }, s2n_stuffer_free);
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&out, 0));
        EXPECT_SUCCESS(s2n_stuffer_write_bytes(&out, wire_bytes, sizeof(wire_bytes)));
        EXPECT_ERROR_WITH_ERRNO(s2n_read_npn_protocol(server_conn, &out), S2N_ERR_NULL);
    };

    /* s2n_read_npn_protocol errors on malformed padding */
    {
        DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER), s2n_connection_ptr_free);
        EXPECT_NOT_NULL(server_conn);

        uint8_t wire_bytes[] = {
            /* Zero-length protocol */
            0x00,
            0x00,
            /* Padding character is not zero */
            0x01,
            0xFF,
        };

        DEFER_CLEANUP(struct s2n_stuffer out = { 0 }, s2n_stuffer_free);
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&out, 0));
        EXPECT_SUCCESS(s2n_stuffer_write_bytes(&out, wire_bytes, sizeof(wire_bytes)));
        EXPECT_ERROR_WITH_ERRNO(s2n_read_npn_protocol(server_conn, &out), S2N_ERR_SAFETY);
    };

    /*
     *= https://datatracker.ietf.org/doc/id/draft-agl-tls-nextprotoneg-03#section-3
     *= type=test
     *# The length of "padding" SHOULD be 32 - ((len(selected_protocol) + 2) % 32).
     */
    {
        struct {
            uint8_t protocol_len;
            uint8_t expected_padding;
        } test_cases[] = {
            { .protocol_len = 0, .expected_padding = 30 },
            { .protocol_len = 32, .expected_padding = 30 },
            { .protocol_len = 17, .expected_padding = 13 },
            { .protocol_len = 2, .expected_padding = 28 },
            { .protocol_len = UINT8_MAX, .expected_padding = 31 },
            { .protocol_len = 30, .expected_padding = 32 },
        };

        for (size_t i = 0; i < s2n_array_len(test_cases); i++) {
            uint8_t output = 0;
            EXPECT_OK(s2n_calculate_padding(test_cases[i].protocol_len, &output));
            EXPECT_EQUAL(output, test_cases[i].expected_padding);
        }
    };
    END_TEST();
}
