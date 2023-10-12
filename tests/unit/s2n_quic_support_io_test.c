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
#include "tls/s2n_connection.h"
#include "tls/s2n_handshake.h"
#include "tls/s2n_quic_support.h"
#include "tls/s2n_tls.h"
#include "utils/s2n_mem.h"

/* We need access to some io logic */
#include "tls/s2n_handshake_io.c"

#define TEST_TICKET_AGE_ADD 0x01, 0x02, 0x03, 0x04
#define TEST_LIFETIME       0x00, 0x01, 0x01, 0x01
#define TEST_TICKET         0x01, 0xFF, 0x23

static const uint8_t TEST_DATA[] = "test";
static const size_t TEST_DATA_SIZE = sizeof(TEST_DATA);

struct s2n_stuffer input_stuffer, output_stuffer;

static int s2n_test_session_ticket_cb(struct s2n_connection *conn, void *ctx, struct s2n_session_ticket *ticket)
{
    uint8_t *count = (uint8_t *) ctx;
    (*count)++;

    return S2N_SUCCESS;
}

static S2N_RESULT s2n_setup_conn(struct s2n_connection *conn)
{
    conn->actual_protocol_version = S2N_TLS13;
    EXPECT_OK(s2n_conn_choose_state_machine(conn, S2N_TLS13));

    RESULT_GUARD_POSIX(s2n_stuffer_wipe(&input_stuffer));
    RESULT_GUARD_POSIX(s2n_stuffer_wipe(&output_stuffer));
    RESULT_GUARD_POSIX(s2n_connection_set_io_stuffers(&input_stuffer, &output_stuffer, conn));

    return S2N_RESULT_OK;
}

static S2N_RESULT s2n_setup_conn_for_client_hello(struct s2n_connection *conn)
{
    RESULT_GUARD(s2n_setup_conn(conn));
    conn->handshake.handshake_type = INITIAL;
    conn->handshake.message_number = 0;
    RESULT_ENSURE_EQ(s2n_conn_get_current_message_type(conn), CLIENT_HELLO);
    return S2N_RESULT_OK;
}

static S2N_RESULT s2n_setup_conn_for_server_hello(struct s2n_connection *conn)
{
    RESULT_GUARD(s2n_setup_conn(conn));

    /* Use arbitrary cipher suite */
    conn->secure->cipher_suite = &s2n_tls13_aes_128_gcm_sha256;

    /* Setup secrets */
    const struct s2n_ecc_preferences *ecc_preferences = NULL;
    RESULT_GUARD_POSIX(s2n_connection_get_ecc_preferences(conn, &ecc_preferences));
    conn->kex_params.server_ecc_evp_params.negotiated_curve = ecc_preferences->ecc_curves[0];
    conn->kex_params.client_ecc_evp_params.negotiated_curve = ecc_preferences->ecc_curves[0];
    if (conn->kex_params.server_ecc_evp_params.evp_pkey == NULL) {
        RESULT_GUARD_POSIX(s2n_ecc_evp_generate_ephemeral_key(&conn->kex_params.server_ecc_evp_params));
    }
    if (conn->kex_params.client_ecc_evp_params.evp_pkey == NULL) {
        RESULT_GUARD_POSIX(s2n_ecc_evp_generate_ephemeral_key(&conn->kex_params.client_ecc_evp_params));
    }

    /* Set handshake to write message */
    conn->handshake.handshake_type = NEGOTIATED | FULL_HANDSHAKE;
    conn->handshake.message_number = 1;
    RESULT_ENSURE_EQ(s2n_conn_get_current_message_type(conn), SERVER_HELLO);

    return S2N_RESULT_OK;
}

static S2N_RESULT s2n_write_test_message(struct s2n_blob *out, message_type_t message_type)
{
    RESULT_GUARD_POSIX(s2n_alloc(out, TEST_DATA_SIZE + TLS_HANDSHAKE_HEADER_LENGTH));

    struct s2n_stuffer stuffer = { 0 };
    RESULT_GUARD_POSIX(s2n_stuffer_init(&stuffer, out));

    RESULT_GUARD_POSIX(s2n_stuffer_write_uint8(&stuffer, message_type));
    RESULT_GUARD_POSIX(s2n_stuffer_write_uint24(&stuffer, TEST_DATA_SIZE));
    RESULT_GUARD_POSIX(s2n_stuffer_write_bytes(&stuffer, TEST_DATA, TEST_DATA_SIZE));

    return S2N_RESULT_OK;
}

static int s2n_test_write_handler(struct s2n_connection *conn)
{
    EXPECT_SUCCESS(s2n_stuffer_write_bytes(&conn->handshake.io, TEST_DATA, TEST_DATA_SIZE));
    return S2N_SUCCESS;
}

static int s2n_test_read_handler(struct s2n_connection *conn)
{
    EXPECT_EQUAL(s2n_stuffer_data_available(&conn->handshake.io), TEST_DATA_SIZE);
    EXPECT_BYTEARRAY_EQUAL(s2n_stuffer_raw_read(&conn->handshake.io, TEST_DATA_SIZE),
            TEST_DATA, TEST_DATA_SIZE);
    return S2N_SUCCESS;
}

int main(int argc, char **argv)
{
    BEGIN_TEST();

    if (!s2n_is_tls13_fully_supported()) {
        END_TEST();
    }

    /* Test: s2n_quic_write_handshake_message */
    {
        /* Safety checks */
        EXPECT_ERROR(s2n_quic_write_handshake_message(NULL));

        /* Writes handshake message */
        {
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));

            uint8_t message_data[] = "The client says hello";
            EXPECT_SUCCESS(s2n_stuffer_write_bytes(&conn->handshake.io, message_data, sizeof(message_data)));

            EXPECT_OK(s2n_quic_write_handshake_message(conn));
            EXPECT_EQUAL(s2n_stuffer_data_available(&conn->out), sizeof(message_data));
            EXPECT_BYTEARRAY_EQUAL(s2n_stuffer_raw_read(&conn->out, sizeof(message_data)),
                    message_data, sizeof(message_data));

            EXPECT_SUCCESS(s2n_connection_free(conn));
        };
    };

    /* Test: s2n_quic_read_handshake_message */
    {
        /* Safety checks */
        {
            struct s2n_connection conn = { 0 };
            uint8_t message_type = 0;

            EXPECT_ERROR(s2n_quic_read_handshake_message(NULL, &message_type));
            EXPECT_ERROR(s2n_quic_read_handshake_message(&conn, NULL));
        };

        /* Reads basic handshake message */
        {
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));

            struct s2n_stuffer stuffer = { 0 };
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
        };

        /* Blocks on insufficient data for handshake message header */
        {
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));

            struct s2n_stuffer stuffer = { 0 };
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&stuffer, 0));
            EXPECT_SUCCESS(s2n_connection_set_io_stuffers(&stuffer, &stuffer, conn));

            EXPECT_SUCCESS(s2n_stuffer_write_uint8(&stuffer, 7));

            uint8_t actual_message_type = 0;
            EXPECT_ERROR_WITH_ERRNO(s2n_quic_read_handshake_message(conn, &actual_message_type),
                    S2N_ERR_IO_BLOCKED);

            EXPECT_SUCCESS(s2n_stuffer_free(&stuffer));
            EXPECT_SUCCESS(s2n_connection_free(conn));
        };

        /* Blocks on insufficient data for handshake message data */
        {
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));

            struct s2n_stuffer stuffer = { 0 };
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
        };

        /* Fails for an impossibly large handshake message */
        {
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));

            struct s2n_stuffer stuffer = { 0 };
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&stuffer, 0));
            EXPECT_SUCCESS(s2n_connection_set_io_stuffers(&stuffer, &stuffer, conn));

            EXPECT_SUCCESS(s2n_stuffer_write_uint8(&stuffer, 7));
            EXPECT_SUCCESS(s2n_stuffer_write_uint24(&stuffer, S2N_MAXIMUM_HANDSHAKE_MESSAGE_LENGTH + 1));

            uint8_t actual_message_type = 0;
            EXPECT_ERROR_WITH_ERRNO(s2n_quic_read_handshake_message(conn, &actual_message_type),
                    S2N_ERR_BAD_MESSAGE);

            EXPECT_SUCCESS(s2n_stuffer_free(&stuffer));
            EXPECT_SUCCESS(s2n_connection_free(conn));
        };
    };

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

        /* Setup config */
        struct s2n_config *config;
        EXPECT_NOT_NULL(config = s2n_config_new());
        EXPECT_SUCCESS(s2n_config_enable_quic(config));

        /* Functional: successfully reads full handshake message */
        {
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));
            EXPECT_OK(s2n_setup_conn_for_server_hello(conn));
            EXPECT_SUCCESS(s2n_connection_set_config(conn, config));

            EXPECT_SUCCESS(s2n_stuffer_write(&input_stuffer, &server_hello));
            EXPECT_FAILURE_WITH_ERRNO(s2n_negotiate(conn, &blocked_status), S2N_ERR_IO_BLOCKED);

            EXPECT_EQUAL(s2n_conn_get_current_message_type(conn), ENCRYPTED_EXTENSIONS);
            EXPECT_EQUAL(s2n_stuffer_data_available(&input_stuffer), 0);

            EXPECT_SUCCESS(s2n_connection_free(conn));
        };

        /* Functional: successfully reads fragmented handshake message */
        for (size_t i = 1; i < server_hello.size - 1; i++) {
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));
            EXPECT_OK(s2n_setup_conn_for_server_hello(conn));
            EXPECT_SUCCESS(s2n_connection_set_config(conn, config));

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
            EXPECT_SUCCESS(s2n_connection_set_config(conn, config));

            DEFER_CLEANUP(struct s2n_blob encrypted_extensions, s2n_free);
            EXPECT_OK(s2n_write_test_message(&encrypted_extensions, TLS_ENCRYPTED_EXTENSIONS));

            EXPECT_SUCCESS(s2n_stuffer_write(&input_stuffer, &server_hello));
            EXPECT_SUCCESS(s2n_stuffer_write(&input_stuffer, &encrypted_extensions));
            EXPECT_FAILURE_WITH_ERRNO(s2n_negotiate(conn, &blocked_status), S2N_ERR_IO_BLOCKED);

            EXPECT_EQUAL(s2n_conn_get_current_message_type(conn), SERVER_CERT);
            EXPECT_EQUAL(s2n_stuffer_data_available(&input_stuffer), 0);

            EXPECT_SUCCESS(s2n_connection_free(conn));
        };

        /* Function: fails to read record instead of handshake message */
        {
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));
            EXPECT_OK(s2n_setup_conn_for_server_hello(conn));
            EXPECT_SUCCESS(s2n_connection_set_config(conn, config));

            /* Write the record: record type, protocol version,
             *                   handshake message size, handshake message */
            POSIX_GUARD(s2n_stuffer_write_uint8(&input_stuffer, TLS_HANDSHAKE));
            POSIX_GUARD(s2n_stuffer_write_uint8(&input_stuffer, 3));
            POSIX_GUARD(s2n_stuffer_write_uint8(&input_stuffer, 3));
            POSIX_GUARD(s2n_stuffer_write_uint16(&input_stuffer, server_hello.size));
            EXPECT_SUCCESS(s2n_stuffer_write(&input_stuffer, &server_hello));

            EXPECT_FAILURE_WITH_ERRNO(s2n_negotiate(conn, &blocked_status), S2N_ERR_BAD_MESSAGE);

            EXPECT_SUCCESS(s2n_connection_free(conn));
        };

        /* Function: fails to read Change Cipher Spec record */
        {
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));
            EXPECT_OK(s2n_setup_conn_for_server_hello(conn));
            EXPECT_SUCCESS(s2n_connection_set_config(conn, config));

            /* Write the record: record type, protocol version,
             *                   record data size, standard "0x01" record data */
            POSIX_GUARD(s2n_stuffer_write_uint8(&input_stuffer, TLS_CHANGE_CIPHER_SPEC));
            POSIX_GUARD(s2n_stuffer_write_uint8(&input_stuffer, 3));
            POSIX_GUARD(s2n_stuffer_write_uint8(&input_stuffer, 3));
            POSIX_GUARD(s2n_stuffer_write_uint16(&input_stuffer, 1));
            POSIX_GUARD(s2n_stuffer_write_uint8(&input_stuffer, 1));

            EXPECT_FAILURE_WITH_ERRNO(s2n_negotiate(conn, &blocked_status), S2N_ERR_BAD_MESSAGE);

            EXPECT_SUCCESS(s2n_connection_free(conn));
        };

        uint32_t client_hello_length = 0;

        /* Functional: successfully writes full handshake message */
        {
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));
            EXPECT_OK(s2n_setup_conn_for_client_hello(conn));
            EXPECT_SUCCESS(s2n_connection_set_config(conn, config));

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
        };

        /* Functional: successfully retries after blocked write */
        {
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));
            EXPECT_OK(s2n_setup_conn_for_client_hello(conn));
            EXPECT_SUCCESS(s2n_connection_set_config(conn, config));

            /* Sabotage the output stuffer to block writing */
            struct s2n_stuffer bad_stuffer = { 0 };
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
        };

        EXPECT_SUCCESS(s2n_stuffer_free(&input_stuffer));
        EXPECT_SUCCESS(s2n_stuffer_free(&output_stuffer));
        EXPECT_SUCCESS(s2n_config_free(config));
    };

    /* Test: s2n_recv_quic_post_handshake_message */
    {
        /* Safety checks */
        s2n_blocked_status blocked = 0;
        EXPECT_FAILURE(s2n_recv_quic_post_handshake_message(NULL, &blocked));

        /* Parsable session ticket message */
        uint8_t ticket_message[] = {
            TLS_SERVER_NEW_SESSION_TICKET,
            0x00, 0x00, 0x12,    /* message size */
            TEST_LIFETIME,       /* ticket lifetime */
            TEST_TICKET_AGE_ADD, /* ticket age add */
            0x02,                /* nonce len */
            0x00, 0x00,          /* nonce */
            0x00, 0x03,          /* ticket len */
            TEST_TICKET,         /* ticket */
            0x00, 0x00,          /* extensions len */
        };

        /* Test: fails to read post-handshake message that is not a ST */
        {
            DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT),
                    s2n_connection_ptr_free);

            DEFER_CLEANUP(struct s2n_stuffer stuffer = { 0 }, s2n_stuffer_free);
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&stuffer, 0));
            EXPECT_SUCCESS(s2n_connection_set_io_stuffers(&stuffer, &stuffer, conn));

            /* Create a post-handshake message that isn't supported by quic */
            EXPECT_SUCCESS(s2n_stuffer_write_uint8(&stuffer, TLS_KEY_UPDATE));
            EXPECT_SUCCESS(s2n_stuffer_write_uint24(&stuffer, TEST_DATA_SIZE));
            EXPECT_SUCCESS(s2n_stuffer_write_bytes(&stuffer, TEST_DATA, TEST_DATA_SIZE));

            EXPECT_FAILURE_WITH_ERRNO(s2n_recv_quic_post_handshake_message(conn, &blocked), S2N_ERR_UNSUPPORTED_WITH_QUIC);
        };

        /* Test: successfully reads and processes post-handshake message */
        {
            DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT),
                    s2n_connection_ptr_free);
            DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
            EXPECT_SUCCESS(s2n_config_set_session_tickets_onoff(config, 1));
            uint8_t session_ticket_cb_count = 0;
            EXPECT_SUCCESS(s2n_config_set_session_ticket_cb(config, s2n_test_session_ticket_cb, &session_ticket_cb_count));
            EXPECT_SUCCESS(s2n_connection_set_config(conn, config));
            conn->secure->cipher_suite = &s2n_tls13_aes_128_gcm_sha256;

            DEFER_CLEANUP(struct s2n_stuffer stuffer = { 0 }, s2n_stuffer_free);
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&stuffer, 0));
            EXPECT_SUCCESS(s2n_connection_set_io_stuffers(&stuffer, &stuffer, conn));

            /* Construct ST handshake message */
            EXPECT_SUCCESS(s2n_stuffer_write_bytes(&stuffer, ticket_message, sizeof(ticket_message)));

            EXPECT_SUCCESS(s2n_recv_quic_post_handshake_message(conn, &blocked));

            /* Callback was triggered */
            EXPECT_EQUAL(session_ticket_cb_count, 1);
        };

        /* Test: successfully reads and processes fragmented post-handshake message */
        for (size_t i = 1; i < sizeof(ticket_message); i++) {
            DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT), s2n_connection_ptr_free);
            DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
            EXPECT_SUCCESS(s2n_config_set_session_tickets_onoff(config, 1));
            uint8_t session_ticket_cb_count = 0;
            EXPECT_SUCCESS(s2n_config_set_session_ticket_cb(config, s2n_test_session_ticket_cb, &session_ticket_cb_count));
            EXPECT_SUCCESS(s2n_connection_set_config(conn, config));
            conn->secure->cipher_suite = &s2n_tls13_aes_128_gcm_sha256;

            DEFER_CLEANUP(struct s2n_stuffer stuffer = { 0 }, s2n_stuffer_free);
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&stuffer, 0));
            EXPECT_SUCCESS(s2n_connection_set_io_stuffers(&stuffer, &stuffer, conn));

            /* Mock receiving a fragmented handshake message */
            EXPECT_SUCCESS(s2n_stuffer_write_bytes(&stuffer, ticket_message, i));

            EXPECT_FAILURE_WITH_ERRNO(s2n_recv_quic_post_handshake_message(conn, &blocked), S2N_ERR_IO_BLOCKED);
            EXPECT_EQUAL(blocked, S2N_BLOCKED_ON_READ);

            /* Callback was not triggered */
            EXPECT_EQUAL(session_ticket_cb_count, 0);

            /* "Write" the rest of the message */
            EXPECT_SUCCESS(s2n_stuffer_write_bytes(&stuffer, ticket_message + i, sizeof(ticket_message) - i));

            EXPECT_SUCCESS(s2n_recv_quic_post_handshake_message(conn, &blocked));

            /* Callback was triggered */
            EXPECT_EQUAL(session_ticket_cb_count, 1);
        };
    }

    END_TEST();
}
