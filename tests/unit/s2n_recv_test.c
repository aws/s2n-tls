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

#include "api/s2n.h"

bool s2n_custom_recv_fn_called = false;

int s2n_expect_concurrent_error_recv_fn(void *io_context, uint8_t *buf, uint32_t len)
{
    struct s2n_connection *conn = (struct s2n_connection*) io_context;
    s2n_custom_recv_fn_called = true;

    s2n_blocked_status blocked = 0;
    ssize_t result = s2n_recv(conn, buf, len, &blocked);
    EXPECT_FAILURE_WITH_ERRNO(result, S2N_ERR_REENTRANCY);
    return result;
}

int main(int argc, char **argv)
{
    BEGIN_TEST();

    DEFER_CLEANUP(struct s2n_cert_chain_and_key *chain_and_key,
            s2n_cert_chain_and_key_ptr_free);
    EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&chain_and_key,
            S2N_DEFAULT_ECDSA_TEST_CERT_CHAIN, S2N_DEFAULT_ECDSA_TEST_PRIVATE_KEY));

    DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(),
            s2n_config_ptr_free);
    EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, chain_and_key));
    EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, "default_tls13"));
    EXPECT_SUCCESS(s2n_config_disable_x509_verification(config));

    /* s2n_peek */
    {
        /* We do full handshakes and send with a real connection here instead of
         * just calling s2n_connection_set_secrets because s2n_peek depends on details
         * of how data is encrypted, and we don't want to make any incorrect assumptions.
         */

        /* Safety check */
        EXPECT_EQUAL(s2n_peek(NULL), 0);

        const uint8_t test_data[100] = "hello world";
        const size_t test_data_size = sizeof(test_data);

        /* s2n_peek reports available plaintext bytes */
        {
            s2n_blocked_status blocked = 0;

            DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT),
                    s2n_connection_ptr_free);
            EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config));
            DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));

            struct s2n_test_io_pair io_pair = { 0 };
            EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
            EXPECT_SUCCESS(s2n_connections_set_io_pair(client_conn, server_conn, &io_pair));
            EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));

            /* Write some data */
            EXPECT_EQUAL(s2n_send(client_conn, test_data, sizeof(test_data), &blocked), sizeof(test_data));

            /* Initially, no data reported as available */
            EXPECT_EQUAL(s2n_peek(server_conn), 0);

            /* Read some, but not all, of the data written */
            uint8_t output[sizeof(test_data)] = { 0 };
            const size_t expected_peek_size = 10;
            const size_t recv_size = test_data_size - expected_peek_size;
            EXPECT_EQUAL(s2n_recv(server_conn, output, recv_size, &blocked), recv_size);

            /* After a partial read, some data reported as available */
            EXPECT_EQUAL(s2n_peek(server_conn), expected_peek_size);

            /* Read the rest of the data */
            EXPECT_EQUAL(s2n_recv(server_conn, output, expected_peek_size, &blocked), expected_peek_size);

            /* After the complete read, no data reported as available */
            EXPECT_EQUAL(s2n_peek(server_conn), 0);
        }

        /* s2n_peek doesn't report bytes belonging to partially read, still encrypted records */
        {
            s2n_blocked_status blocked = 0;

            DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT),
                    s2n_connection_ptr_free);
            EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config));
            DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));

            /* Use stuffers for IO so that we can trigger a block on a read */
            DEFER_CLEANUP(struct s2n_stuffer server_in = { 0 }, s2n_stuffer_free);
            DEFER_CLEANUP(struct s2n_stuffer server_out = { 0 }, s2n_stuffer_free);
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&server_in, 0));
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&server_out, 0));
            EXPECT_SUCCESS(s2n_connection_set_io_stuffers(&server_out, &server_in, client_conn));
            EXPECT_SUCCESS(s2n_connection_set_io_stuffers(&server_in, &server_out, server_conn));

            EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));

            /* Write some data */
            EXPECT_EQUAL(s2n_send(client_conn, test_data, sizeof(test_data), &blocked), sizeof(test_data));

            /* Drop some of the data */
            EXPECT_SUCCESS(s2n_stuffer_wipe_n(&server_in, 10));

            /* Try to read the data, but block */
            uint8_t output[sizeof(test_data)] = { 0 };
            EXPECT_FAILURE_WITH_ERRNO(s2n_recv(server_conn, output, sizeof(test_data), &blocked),
                    S2N_ERR_IO_BLOCKED);

            /* conn->in contains data, but s2n_peek reports no data available */
            EXPECT_TRUE(s2n_stuffer_data_available(&server_conn->in));
            EXPECT_EQUAL(s2n_peek(server_conn), 0);
        }

        /* s2n_peek doesn't report bytes belonging to post-handshake messages */
        {
            s2n_blocked_status blocked = 0;

            DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT),
                    s2n_connection_ptr_free);
            EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config));
            DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));

            /* Use stuffers for IO so that we can trigger a block on a read */
            DEFER_CLEANUP(struct s2n_stuffer server_in = { 0 }, s2n_stuffer_free);
            DEFER_CLEANUP(struct s2n_stuffer server_out = { 0 }, s2n_stuffer_free);
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&server_in, 0));
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&server_out, 0));
            EXPECT_SUCCESS(s2n_connection_set_io_stuffers(&server_out, &server_in, client_conn));
            EXPECT_SUCCESS(s2n_connection_set_io_stuffers(&server_in, &server_out, server_conn));

            EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));

            /* Send a KeyUpdate message */
            client_conn->key_update_pending = true;
            EXPECT_SUCCESS(s2n_key_update_send(client_conn, &blocked));
            EXPECT_FALSE(client_conn->key_update_pending);

            /* Drop some of the data */
            EXPECT_SUCCESS(s2n_stuffer_wipe_n(&server_in, 10));

            /* Try to read the KeyUpdate message, but block */
            uint8_t output[1] = { 0 };
            EXPECT_FAILURE_WITH_ERRNO(s2n_recv(server_conn, output, sizeof(output), &blocked),
                    S2N_ERR_IO_BLOCKED);

            /* conn->in contains data, but s2n_peek reports no data available */
            EXPECT_TRUE(s2n_stuffer_data_available(&server_conn->in));
            EXPECT_EQUAL(s2n_peek(server_conn), 0);
        }
    }

    /* s2n_recv cannot be called concurrently */
    {
        /* Setup connection */
        struct s2n_connection *conn;
        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));

        /* Setup bad recv callback */
        EXPECT_SUCCESS(s2n_connection_set_recv_cb(conn, s2n_expect_concurrent_error_recv_fn));
        EXPECT_SUCCESS(s2n_connection_set_recv_ctx(conn, (void*) conn));
        EXPECT_SUCCESS(s2n_connection_set_blinding(conn, S2N_SELF_SERVICE_BLINDING));

        uint8_t test_data[100] = { 0 };
        s2n_blocked_status blocked = 0;
        s2n_custom_recv_fn_called = false;
        EXPECT_FAILURE_WITH_ERRNO(s2n_recv(conn, test_data, sizeof(test_data), &blocked),
                S2N_ERR_IO);
        EXPECT_TRUE(s2n_custom_recv_fn_called);

        /* Cleanup */
        EXPECT_SUCCESS(s2n_connection_free(conn));
    }

    END_TEST();
}
