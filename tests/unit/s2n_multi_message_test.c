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
#include "tls/s2n_tls.h"
/* Just to get access to advance_message */
#include "tls/s2n_handshake_io.c"

struct test_data {
    uint8_t message_type;
    int (*handler)(struct s2n_connection *conn);
};

struct s2n_cert_cb_ctx {
    struct s2n_cert_validation_info *info;
};

static int s2n_test_cert_validation_callback(struct s2n_connection *conn, struct s2n_cert_validation_info *info, void *ctx)
{
    struct s2n_cert_cb_ctx *data = (struct s2n_cert_cb_ctx *) ctx;

    data->info = info;

    /* Returning success since we will accept asynchronously */
    return S2N_SUCCESS;
}

int main(int argc, char **argv)
{
    BEGIN_TEST();

    DEFER_CLEANUP(struct s2n_cert_chain_and_key *chain_and_key = NULL, s2n_cert_chain_and_key_ptr_free);
    EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&chain_and_key,
            S2N_DEFAULT_TEST_CERT_CHAIN, S2N_DEFAULT_TEST_PRIVATE_KEY));

    struct s2n_config *server_config = s2n_config_new();
    EXPECT_NOT_NULL(server_config);
    /* Policy that will negotiate TLS1.3 */
    EXPECT_SUCCESS(s2n_config_set_cipher_preferences(server_config, "20251014"));
    EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(server_config, chain_and_key));
    EXPECT_SUCCESS(s2n_config_set_verification_ca_location(server_config, S2N_DEFAULT_TEST_CERT_CHAIN, NULL));
    EXPECT_SUCCESS(s2n_config_set_client_auth_type(server_config, S2N_CERT_AUTH_REQUIRED));

    struct s2n_config *client_config = s2n_config_new();
    EXPECT_NOT_NULL(client_config);
    /* Policy that will negotiate TLS1.3 */
    EXPECT_SUCCESS(s2n_config_set_cipher_preferences(client_config, "20251014"));
    EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(client_config, chain_and_key));
    EXPECT_SUCCESS(s2n_config_set_verification_ca_location(client_config, S2N_DEFAULT_TEST_CERT_CHAIN, NULL));
    EXPECT_SUCCESS(s2n_config_set_client_auth_type(client_config, S2N_CERT_AUTH_REQUIRED));

    /* This test checks that s2n-tls can receive multiple handshake messages in one record. This is
     * not a comprehensive test, it only tests the usecase where an async callback is triggered
     * while reading multiple TLS messages in a single record.
     */
    {
        struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT);
        EXPECT_NOT_NULL(client_conn);
        EXPECT_SUCCESS(s2n_set_server_name(client_conn, "localhost"));
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, client_config));
        EXPECT_SUCCESS(s2n_connection_set_blinding(client_conn, S2N_SELF_SERVICE_BLINDING));

        struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER);
        EXPECT_NOT_NULL(server_conn);

        /* Add a cert validation callback. In this case we will store the cert validation info
         * when the callback triggers and accept the cert outside of the callback. */
        struct s2n_cert_cb_ctx cb_ctx = { 0 };
        EXPECT_SUCCESS(s2n_config_set_cert_validation_cb(server_config, s2n_test_cert_validation_callback, &cb_ctx));
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, server_config));
        EXPECT_SUCCESS(s2n_connection_set_blinding(server_conn, S2N_SELF_SERVICE_BLINDING));

        DEFER_CLEANUP(struct s2n_test_io_pair io_pair = { 0 }, s2n_io_pair_close);
        EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
        EXPECT_SUCCESS(s2n_connections_set_io_pair(client_conn, server_conn, &io_pair));

        /* Stop client before sending its last flight of messages */
        EXPECT_OK(s2n_negotiate_test_server_and_client_until_message(server_conn, client_conn, CLIENT_CERT));

        struct test_data message_arr[] = {
            { .message_type = TLS_CERTIFICATE, .handler = s2n_client_cert_send },
            { .message_type = TLS_CERT_VERIFY, .handler = s2n_tls13_cert_verify_send },
            { .message_type = TLS_FINISHED, .handler = s2n_tls13_client_finished_send }
        };

        /* We have to manually call the state machine handler and update the handshake hashes
         * because s2n-tls is not designed to send multiple handshake messages per record. */
        for (size_t i = 0; i < s2n_array_len(message_arr); i++) {
            /* Write handshake message */
            EXPECT_SUCCESS(s2n_stuffer_write_uint8(&client_conn->handshake.io, message_arr[i].message_type));
            struct s2n_stuffer_reservation reservation = { 0 };
            EXPECT_SUCCESS(s2n_stuffer_reserve_uint24(&client_conn->handshake.io, &reservation));
            EXPECT_SUCCESS(message_arr[i].handler(client_conn));
            EXPECT_SUCCESS(s2n_stuffer_write_vector_size(&reservation));
            EXPECT_SUCCESS(s2n_advance_message(client_conn));

            /* Update transcript hash with handshake message */
            struct s2n_blob data = { 0 };
            uint32_t len = s2n_stuffer_data_available(&client_conn->handshake.io);
            uint8_t *bytes = s2n_stuffer_raw_read(&client_conn->handshake.io, len);
            EXPECT_NOT_NULL(bytes);
            EXPECT_SUCCESS(s2n_blob_init(&data, bytes, len));
            EXPECT_SUCCESS(s2n_conn_update_handshake_hashes(client_conn, &data));
            EXPECT_SUCCESS(s2n_stuffer_skip_read(&client_conn->handshake.io,
                    s2n_stuffer_data_available(&client_conn->handshake.io)));
        }

        EXPECT_SUCCESS(s2n_stuffer_reread(&client_conn->handshake.io));

        /* Writes all messages in the handshake buffer to the same record */
        s2n_blocked_status blocked = S2N_NOT_BLOCKED;
        EXPECT_OK(s2n_handshake_message_send(client_conn, TLS_HANDSHAKE, &blocked));

        /* Handshake will block until the server accepts the client cert */
        for (int i = 0; i < 3; i++) {
            EXPECT_FAILURE_WITH_ERRNO(s2n_negotiate_test_server_and_client(server_conn, client_conn),
                    S2N_ERR_ASYNC_BLOCKED);
        }
        EXPECT_SUCCESS(s2n_cert_validation_accept(cb_ctx.info));

        /* Handshake completes successfully after server accepts client cert */
        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));
    }

    END_TEST();
}
