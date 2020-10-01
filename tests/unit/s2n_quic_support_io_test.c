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
#include "tls/s2n_quic_support.h"

#include "tls/s2n_connection.h"
#include "tls/s2n_handshake.h"
#include "tls/s2n_tls.h"
#include "utils/s2n_mem.h"

/* We need access to some io logic */
#include "tls/s2n_handshake_io.c"

static const uint8_t TEST_DATA[] = "test";
static const size_t TEST_DATA_SIZE = sizeof(TEST_DATA);

struct s2n_stuffer input_stuffer, output_stuffer;
static S2N_RESULT s2n_setup_conn(struct s2n_connection *conn)
{
    GUARD_AS_RESULT(s2n_connection_enable_quic(conn));
    conn->actual_protocol_version = S2N_TLS13;

    GUARD_AS_RESULT(s2n_stuffer_wipe(&input_stuffer));
    GUARD_AS_RESULT(s2n_stuffer_wipe(&output_stuffer));
    GUARD_AS_RESULT(s2n_connection_set_io_stuffers(&input_stuffer, &output_stuffer, conn));

    return S2N_RESULT_OK;
}

static S2N_RESULT s2n_setup_conn_for_client_hello(struct s2n_connection *conn)
{
    GUARD_RESULT(s2n_setup_conn(conn));
    conn->handshake.handshake_type = INITIAL;
    conn->handshake.message_number = 0;
    ENSURE_EQ(s2n_conn_get_current_message_type(conn), CLIENT_HELLO);
    return S2N_RESULT_OK;
}

static S2N_RESULT s2n_setup_conn_for_server_hello(struct s2n_connection *conn)
{
    GUARD_RESULT(s2n_setup_conn(conn));

    /* Use arbitrary cipher suite */
    conn->secure.cipher_suite = &s2n_tls13_aes_128_gcm_sha256;

    /* Setup secrets */
    const struct s2n_ecc_preferences *ecc_preferences = NULL;
    GUARD_AS_RESULT(s2n_connection_get_ecc_preferences(conn, &ecc_preferences));
    conn->secure.server_ecc_evp_params.negotiated_curve = ecc_preferences->ecc_curves[0];
    conn->secure.client_ecc_evp_params[0].negotiated_curve = ecc_preferences->ecc_curves[0];
    if(conn->secure.server_ecc_evp_params.evp_pkey == NULL) {
        GUARD_AS_RESULT(s2n_ecc_evp_generate_ephemeral_key(&conn->secure.server_ecc_evp_params));
    }
    if(conn->secure.client_ecc_evp_params[0].evp_pkey == NULL) {
        GUARD_AS_RESULT(s2n_ecc_evp_generate_ephemeral_key(&conn->secure.client_ecc_evp_params[0]));
    }

    /* Set handshake to write message */
    conn->handshake.handshake_type = NEGOTIATED | FULL_HANDSHAKE;
    conn->handshake.message_number = 1;
    ENSURE_EQ(s2n_conn_get_current_message_type(conn), SERVER_HELLO);

    return S2N_RESULT_OK;
}

static S2N_RESULT s2n_write_test_message(struct s2n_blob *out, message_type_t message_type)
{
    GUARD_AS_RESULT(s2n_alloc(out, TEST_DATA_SIZE + TLS_HANDSHAKE_HEADER_LENGTH));

    struct s2n_stuffer stuffer;
    GUARD_AS_RESULT(s2n_stuffer_init(&stuffer, out));

    GUARD_AS_RESULT(s2n_stuffer_write_uint8(&stuffer, message_type));
    GUARD_AS_RESULT(s2n_stuffer_write_uint24(&stuffer, TEST_DATA_SIZE));
    GUARD_AS_RESULT(s2n_stuffer_write_bytes(&stuffer, TEST_DATA, TEST_DATA_SIZE));

    return S2N_RESULT_OK;
}

static int s2n_test_write_handler(struct s2n_connection* conn)
{
    EXPECT_SUCCESS(s2n_stuffer_write_bytes(&conn->handshake.io, TEST_DATA, TEST_DATA_SIZE));
    return S2N_SUCCESS;
}

static int s2n_test_read_handler(struct s2n_connection* conn)
{
    EXPECT_EQUAL(s2n_stuffer_data_available(&conn->handshake.io), TEST_DATA_SIZE);
    EXPECT_BYTEARRAY_EQUAL(s2n_stuffer_raw_read(&conn->handshake.io, TEST_DATA_SIZE),
            TEST_DATA, TEST_DATA_SIZE);
    return S2N_SUCCESS;
}

int main(int argc, char **argv)
{
    BEGIN_TEST();
    EXPECT_SUCCESS(s2n_enable_tls13());

    /* Test: s2n_quic_write_handshake_message */
    {
        /* Safety checks */
        {
            struct s2n_connection conn = { 0 };
            struct s2n_blob blob = { 0 };

            EXPECT_ERROR(s2n_quic_write_handshake_message(NULL, &blob));
            EXPECT_ERROR(s2n_quic_write_handshake_message(&conn, NULL));
        }

        /* Writes handshake message */
        {
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));

            uint8_t message_data[] = "The client says hello";
            struct s2n_blob in;
            EXPECT_SUCCESS(s2n_blob_init(&in, message_data, sizeof(message_data)));

            EXPECT_OK(s2n_quic_write_handshake_message(conn, &in));
            EXPECT_EQUAL(s2n_stuffer_data_available(&conn->out), sizeof(message_data));
            EXPECT_BYTEARRAY_EQUAL(s2n_stuffer_raw_read(&conn->out, sizeof(message_data)),
                    message_data, sizeof(message_data));

            EXPECT_SUCCESS(s2n_connection_free(conn));
        }
    }

    /* Test: s2n_quic_read_handshake_message */
    {
        /* Safety checks */
        {
            struct s2n_connection conn = { 0 };
            uint8_t message_type = 0;

            EXPECT_ERROR(s2n_quic_read_handshake_message(NULL, &message_type));
            EXPECT_ERROR(s2n_quic_read_handshake_message(&conn, NULL));
        }

        /* Reads basic handshake message */
        {
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));

            struct s2n_stuffer stuffer;
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&stuffer, 0));
            EXPECT_SUCCESS(s2n_connection_set_io_stuffers(&stuffer, &stuffer, conn));

            uint8_t expected_message_type = 7;
            EXPECT_SUCCESS(s2n_stuffer_write_uint8(&stuffer, expected_message_type));
            EXPECT_SUCCESS(s2n_stuffer_write_uint24(&stuffer, TEST_DATA_SIZE));
            EXPECT_SUCCESS(s2n_stuffer_write_bytes(&stuffer, TEST_DATA, TEST_DATA_SIZE));

            uint8_t actual_message_type = 0;
            EXPECT_OK(s2n_quic_read_handshake_message(conn, &actual_message_type));

            EXPECT_EQUAL(actual_message_type, expected_message_type);
            EXPECT_EQUAL(s2n_stuffer_data_available(&conn->handshake.io), TLS_HANDSHAKE_HEADER_LENGTH);
            EXPECT_EQUAL(s2n_stuffer_data_available(&conn->in), TEST_DATA_SIZE);
            EXPECT_BYTEARRAY_EQUAL(s2n_stuffer_raw_read(&conn->in, TEST_DATA_SIZE),
                    TEST_DATA, sizeof(TEST_DATA));

            EXPECT_SUCCESS(s2n_stuffer_free(&stuffer));
            EXPECT_SUCCESS(s2n_connection_free(conn));
        }

        /* Blocks on insufficient data for handshake message header */
        {
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));

            struct s2n_stuffer stuffer;
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&stuffer, 0));
            EXPECT_SUCCESS(s2n_connection_set_io_stuffers(&stuffer, &stuffer, conn));

            EXPECT_SUCCESS(s2n_stuffer_write_uint8(&stuffer, 7));

            uint8_t actual_message_type = 0;
            EXPECT_ERROR_WITH_ERRNO(s2n_quic_read_handshake_message(conn, &actual_message_type),
                    S2N_ERR_IO_BLOCKED);

            EXPECT_SUCCESS(s2n_stuffer_free(&stuffer));
            EXPECT_SUCCESS(s2n_connection_free(conn));
        }

        /* Blocks on insufficient data for handshake message data */
        {
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));

            struct s2n_stuffer stuffer;
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&stuffer, 0));
            EXPECT_SUCCESS(s2n_connection_set_io_stuffers(&stuffer, &stuffer, conn));

            EXPECT_SUCCESS(s2n_stuffer_write_uint8(&stuffer, 7));
            EXPECT_SUCCESS(s2n_stuffer_write_uint24(&stuffer, TEST_DATA_SIZE));
            EXPECT_SUCCESS(s2n_stuffer_write_bytes(&stuffer, TEST_DATA, TEST_DATA_SIZE - 1));

            uint8_t actual_message_type = 0;
            EXPECT_ERROR_WITH_ERRNO(s2n_quic_read_handshake_message(conn, &actual_message_type),
                    S2N_ERR_IO_BLOCKED);

            EXPECT_SUCCESS(s2n_stuffer_free(&stuffer));
            EXPECT_SUCCESS(s2n_connection_free(conn));
        }

        /* Fails for an impossibly large handshake message */
        {
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));

            struct s2n_stuffer stuffer;
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&stuffer, 0));
            EXPECT_SUCCESS(s2n_connection_set_io_stuffers(&stuffer, &stuffer, conn));

            EXPECT_SUCCESS(s2n_stuffer_write_uint8(&stuffer, 7));
            EXPECT_SUCCESS(s2n_stuffer_write_uint24(&stuffer, S2N_MAXIMUM_HANDSHAKE_MESSAGE_LENGTH + 1));

            uint8_t actual_message_type = 0;
            EXPECT_ERROR_WITH_ERRNO(s2n_quic_read_handshake_message(conn, &actual_message_type),
                    S2N_ERR_BAD_MESSAGE);

            EXPECT_SUCCESS(s2n_stuffer_free(&stuffer));
            EXPECT_SUCCESS(s2n_connection_free(conn));
        }
    }

    /* Functional Tests */
    {
        s2n_blocked_status blocked_status;

        /* Use handler stubs to avoid executing complicated handler implementations */
        for (size_t i = 0; i < s2n_array_len(tls13_state_machine); i++) {
            tls13_state_machine[i].handler[S2N_SERVER] = s2n_test_read_handler;
            tls13_state_machine[i].handler[S2N_CLIENT] = s2n_test_write_handler;
        }

        /* Write test message */
        DEFER_CLEANUP(struct s2n_blob server_hello, s2n_free);
        EXPECT_OK(s2n_write_test_message(&server_hello, TLS_SERVER_HELLO));

        /* Setup IO buffers */
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&input_stuffer, 0));
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&output_stuffer, 0));

        /* Functional: successfully reads full handshake message */
        {
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));
            EXPECT_OK(s2n_setup_conn_for_server_hello(conn));

            EXPECT_SUCCESS(s2n_stuffer_write(&input_stuffer, &server_hello));
            EXPECT_FAILURE_WITH_ERRNO(s2n_negotiate(conn, &blocked_status), S2N_ERR_IO_BLOCKED);

            EXPECT_EQUAL(s2n_conn_get_current_message_type(conn), ENCRYPTED_EXTENSIONS);
            EXPECT_EQUAL(s2n_stuffer_data_available(&input_stuffer), 0);

            EXPECT_SUCCESS(s2n_connection_free(conn));
        }

        /* Functional: successfully reads fragmented handshake message */
        for(size_t i = 1; i < server_hello.size - 1; i++) {
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));
            EXPECT_OK(s2n_setup_conn_for_server_hello(conn));

            /* Write initial fragment */
            EXPECT_SUCCESS(s2n_stuffer_write_bytes(&input_stuffer, server_hello.data, i));
            EXPECT_FAILURE_WITH_ERRNO(s2n_negotiate(conn, &blocked_status), S2N_ERR_IO_BLOCKED);

            EXPECT_EQUAL(s2n_conn_get_current_message_type(conn), SERVER_HELLO);
            EXPECT_EQUAL(s2n_stuffer_data_available(&input_stuffer), 0);

            /* Write rest of message */
            EXPECT_SUCCESS(s2n_stuffer_write_bytes(&input_stuffer,
                    server_hello.data + i, server_hello.size - i));
            EXPECT_FAILURE_WITH_ERRNO(s2n_negotiate(conn, &blocked_status), S2N_ERR_IO_BLOCKED);

            EXPECT_EQUAL(s2n_conn_get_current_message_type(conn), ENCRYPTED_EXTENSIONS);
            EXPECT_EQUAL(s2n_stuffer_data_available(&input_stuffer), 0);

            EXPECT_SUCCESS(s2n_connection_free(conn));
        }

        /* Functional: successfully reads multiple handshake messages */
        {
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));
            EXPECT_OK(s2n_setup_conn_for_server_hello(conn));

            DEFER_CLEANUP(struct s2n_blob encrypted_extensions, s2n_free);
            EXPECT_OK(s2n_write_test_message(&encrypted_extensions, TLS_ENCRYPTED_EXTENSIONS));

            EXPECT_SUCCESS(s2n_stuffer_write(&input_stuffer, &server_hello));
            EXPECT_SUCCESS(s2n_stuffer_write(&input_stuffer, &encrypted_extensions));
            EXPECT_FAILURE_WITH_ERRNO(s2n_negotiate(conn, &blocked_status), S2N_ERR_IO_BLOCKED);

            EXPECT_EQUAL(s2n_conn_get_current_message_type(conn), SERVER_CERT);
            EXPECT_EQUAL(s2n_stuffer_data_available(&input_stuffer), 0);

            EXPECT_SUCCESS(s2n_connection_free(conn));
        }

        /* Function: fails to read record instead of handshake message */
        {
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));
            EXPECT_OK(s2n_setup_conn_for_server_hello(conn));

            /* Write the record: record type, protocol version,
             *                   handshake message size, handshake message */
            GUARD(s2n_stuffer_write_uint8(&input_stuffer, TLS_HANDSHAKE));
            GUARD(s2n_stuffer_write_uint8(&input_stuffer, 3));
            GUARD(s2n_stuffer_write_uint8(&input_stuffer, 3));
            GUARD(s2n_stuffer_write_uint16(&input_stuffer, server_hello.size));
            EXPECT_SUCCESS(s2n_stuffer_write(&input_stuffer, &server_hello));

            EXPECT_FAILURE_WITH_ERRNO(s2n_negotiate(conn, &blocked_status), S2N_ERR_BAD_MESSAGE);

            EXPECT_SUCCESS(s2n_connection_free(conn));
        }

        /* Function: fails to read Change Cipher Spec record */
        {
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));
            EXPECT_OK(s2n_setup_conn_for_server_hello(conn));

            /* Write the record: record type, protocol version,
             *                   record data size, standard "0x01" record data */
            GUARD(s2n_stuffer_write_uint8(&input_stuffer, TLS_CHANGE_CIPHER_SPEC));
            GUARD(s2n_stuffer_write_uint8(&input_stuffer, 3));
            GUARD(s2n_stuffer_write_uint8(&input_stuffer, 3));
            GUARD(s2n_stuffer_write_uint16(&input_stuffer, 1));
            GUARD(s2n_stuffer_write_uint8(&input_stuffer, 1));

            EXPECT_FAILURE_WITH_ERRNO(s2n_negotiate(conn, &blocked_status), S2N_ERR_BAD_MESSAGE);

            EXPECT_SUCCESS(s2n_connection_free(conn));
        }

        uint32_t client_hello_length = 0;

        /* Functional: successfully writes full handshake message */
        {
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));
            EXPECT_OK(s2n_setup_conn_for_client_hello(conn));

            EXPECT_FAILURE_WITH_ERRNO(s2n_negotiate(conn, &blocked_status), S2N_ERR_IO_BLOCKED);
            client_hello_length = s2n_stuffer_data_available(&output_stuffer);

            uint8_t actual_message_type;
            EXPECT_SUCCESS(s2n_stuffer_read_uint8(&output_stuffer, &actual_message_type));
            EXPECT_EQUAL(actual_message_type, TLS_CLIENT_HELLO);

            uint32_t actual_message_size;
            EXPECT_SUCCESS(s2n_stuffer_read_uint24(&output_stuffer, &actual_message_size));
            EXPECT_EQUAL(actual_message_size, TEST_DATA_SIZE);

            EXPECT_EQUAL(s2n_stuffer_data_available(&output_stuffer), TEST_DATA_SIZE);
            EXPECT_BYTEARRAY_EQUAL(s2n_stuffer_raw_read(&output_stuffer, TEST_DATA_SIZE),
                    TEST_DATA, TEST_DATA_SIZE);

            EXPECT_EQUAL(s2n_conn_get_current_message_type(conn), SERVER_HELLO);

            EXPECT_SUCCESS(s2n_connection_free(conn));
        }

        /* Functional: successfully retries after blocked write */
        {
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));
            EXPECT_OK(s2n_setup_conn_for_client_hello(conn));

            /* Sabotage the output stuffer to block writing */
            struct s2n_stuffer bad_stuffer;
            EXPECT_SUCCESS(s2n_connection_set_io_stuffers(&input_stuffer, &bad_stuffer, conn));

            EXPECT_FAILURE_WITH_ERRNO(s2n_negotiate(conn, &blocked_status), S2N_ERR_IO_BLOCKED);
            EXPECT_EQUAL(s2n_conn_get_current_message_type(conn), CLIENT_HELLO);
            EXPECT_EQUAL(s2n_stuffer_data_available(&output_stuffer), 0);

            /* Fix the output stuffer */
            EXPECT_SUCCESS(s2n_connection_set_io_stuffers(&input_stuffer, &output_stuffer, conn));

            EXPECT_FAILURE_WITH_ERRNO(s2n_negotiate(conn, &blocked_status), S2N_ERR_IO_BLOCKED);
            EXPECT_EQUAL(s2n_conn_get_current_message_type(conn), SERVER_HELLO);
            EXPECT_EQUAL(s2n_stuffer_data_available(&output_stuffer), client_hello_length);

            EXPECT_SUCCESS(s2n_connection_free(conn));
        }

        EXPECT_SUCCESS(s2n_stuffer_free(&input_stuffer));
        EXPECT_SUCCESS(s2n_stuffer_free(&output_stuffer));
    }

    END_TEST();
}
