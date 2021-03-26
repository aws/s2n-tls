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

int main(int argc, char **argv)
{
    BEGIN_TEST();

    /* Verify successful shutdown. Server only. */
    {
        /* Setup connections */
        struct s2n_connection *client_conn, *server_conn;
        EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));

        /* Setup config */
        struct s2n_cert_chain_and_key *chain_and_key;
        EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&chain_and_key,
                S2N_DEFAULT_ECDSA_TEST_CERT_CHAIN, S2N_DEFAULT_ECDSA_TEST_PRIVATE_KEY));
        struct s2n_config *config;
        EXPECT_NOT_NULL(config = s2n_config_new());
        EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, "default_tls13"));
        EXPECT_SUCCESS(s2n_config_set_unsafe_for_testing(config));
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, chain_and_key));
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config));
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));

        /* Create nonblocking pipes */
        struct s2n_test_io_pair io_pair;
        EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
        EXPECT_SUCCESS(s2n_connection_set_io_pair(client_conn, &io_pair));
        EXPECT_SUCCESS(s2n_connection_set_io_pair(server_conn, &io_pair));

        /* Verify state prior to alert */
        EXPECT_FALSE(server_conn->close_notify_received);
        EXPECT_FALSE(client_conn->close_notify_received);

        s2n_blocked_status server_blocked;

        /* Verify successful shutdown. Server initiated. */
        EXPECT_FAILURE_WITH_ERRNO(s2n_shutdown(server_conn, &server_blocked), S2N_ERR_IO_BLOCKED);

        /* Verify state after alert */
        EXPECT_SUCCESS(server_conn->close_notify_received);
        EXPECT_SUCCESS(client_conn->close_notify_received);

        /* Cleanup */
        EXPECT_SUCCESS(s2n_connection_free(server_conn));
        EXPECT_SUCCESS(s2n_connection_free(client_conn));
        EXPECT_SUCCESS(s2n_io_pair_close(&io_pair));
        EXPECT_SUCCESS(s2n_cert_chain_and_key_free(chain_and_key));
        EXPECT_SUCCESS(s2n_config_free(config));
    }

    /* Verify successful shutdown. Client only. */
    {
        /* Setup connections */
        struct s2n_connection *client_conn, *server_conn;
        EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));

        /* Setup config */
        struct s2n_cert_chain_and_key *chain_and_key;
        EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&chain_and_key,
                S2N_DEFAULT_ECDSA_TEST_CERT_CHAIN, S2N_DEFAULT_ECDSA_TEST_PRIVATE_KEY));
        struct s2n_config *config;
        EXPECT_NOT_NULL(config = s2n_config_new());
        EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, "default_tls13"));
        EXPECT_SUCCESS(s2n_config_set_unsafe_for_testing(config));
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, chain_and_key));
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config));
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));

        /* Create nonblocking pipes */
        struct s2n_test_io_pair io_pair;
        EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
        EXPECT_SUCCESS(s2n_connection_set_io_pair(client_conn, &io_pair));
        EXPECT_SUCCESS(s2n_connection_set_io_pair(server_conn, &io_pair));

        /* Verify state prior to alert */
        EXPECT_FALSE(server_conn->close_notify_received);
        EXPECT_FALSE(client_conn->close_notify_received);

        s2n_blocked_status client_blocked;

        /* Verify successful shutdown. Server initiated. */
        EXPECT_FAILURE_WITH_ERRNO(s2n_shutdown(client_conn, &client_blocked), S2N_ERR_IO_BLOCKED);

        /* Verify state after alert */
        EXPECT_SUCCESS(server_conn->close_notify_received);
        EXPECT_SUCCESS(client_conn->close_notify_received);

        /* Cleanup */
        EXPECT_SUCCESS(s2n_connection_free(server_conn));
        EXPECT_SUCCESS(s2n_connection_free(client_conn));
        EXPECT_SUCCESS(s2n_io_pair_close(&io_pair));
        EXPECT_SUCCESS(s2n_cert_chain_and_key_free(chain_and_key));
        EXPECT_SUCCESS(s2n_config_free(config));
    }

    /* Verify successful shutdown. Server initiated. */
    {
        /* Setup connections */
        struct s2n_connection *client_conn, *server_conn;
        EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));

        /* Setup config */
        struct s2n_cert_chain_and_key *chain_and_key;
        EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&chain_and_key,
                S2N_DEFAULT_ECDSA_TEST_CERT_CHAIN, S2N_DEFAULT_ECDSA_TEST_PRIVATE_KEY));
        struct s2n_config *config;
        EXPECT_NOT_NULL(config = s2n_config_new());
        EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, "default_tls13"));
        EXPECT_SUCCESS(s2n_config_set_unsafe_for_testing(config));
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, chain_and_key));
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config));
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));

        /* Create nonblocking pipes */
        struct s2n_test_io_pair io_pair;
        EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
        EXPECT_SUCCESS(s2n_connection_set_io_pair(client_conn, &io_pair));
        EXPECT_SUCCESS(s2n_connection_set_io_pair(server_conn, &io_pair));

        /* Verify state prior to alert */
        EXPECT_FALSE(server_conn->close_notify_received);
        EXPECT_FALSE(client_conn->close_notify_received);

        s2n_blocked_status server_blocked;
        s2n_blocked_status client_blocked;

        /* Verify successful shutdown. Server initiated. */
        EXPECT_FAILURE_WITH_ERRNO(s2n_shutdown(server_conn, &server_blocked), S2N_ERR_IO_BLOCKED);
        EXPECT_SUCCESS(s2n_shutdown(client_conn, &client_blocked));
        EXPECT_SUCCESS(s2n_shutdown(server_conn, &server_blocked));

        /* Verify state after alert */
        EXPECT_SUCCESS(server_conn->close_notify_received);
        EXPECT_SUCCESS(client_conn->close_notify_received);

        /* Cleanup */
        EXPECT_SUCCESS(s2n_connection_free(server_conn));
        EXPECT_SUCCESS(s2n_connection_free(client_conn));
        EXPECT_SUCCESS(s2n_io_pair_close(&io_pair));
        EXPECT_SUCCESS(s2n_cert_chain_and_key_free(chain_and_key));
        EXPECT_SUCCESS(s2n_config_free(config));
    }

    /* Verify successful shutdown. Client initiated. */
    {
        /* Setup connections */
        struct s2n_connection *client_conn, *server_conn;
        EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));

        /* Setup config */
        struct s2n_cert_chain_and_key *chain_and_key;
        EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&chain_and_key,
                S2N_DEFAULT_ECDSA_TEST_CERT_CHAIN, S2N_DEFAULT_ECDSA_TEST_PRIVATE_KEY));
        struct s2n_config *config;
        EXPECT_NOT_NULL(config = s2n_config_new());
        EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, "default_tls13"));
        EXPECT_SUCCESS(s2n_config_set_unsafe_for_testing(config));
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, chain_and_key));
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config));
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));

        /* Create nonblocking pipes */
        struct s2n_test_io_pair io_pair;
        EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
        EXPECT_SUCCESS(s2n_connection_set_io_pair(client_conn, &io_pair));
        EXPECT_SUCCESS(s2n_connection_set_io_pair(server_conn, &io_pair));

        /* Verify state prior to alert */
        EXPECT_FALSE(server_conn->close_notify_received);
        EXPECT_FALSE(client_conn->close_notify_received);

        s2n_blocked_status server_blocked;
        s2n_blocked_status client_blocked;

        /* Verify successful shutdown. Server initiated. */
        EXPECT_FAILURE_WITH_ERRNO(s2n_shutdown(client_conn, &client_blocked), S2N_ERR_IO_BLOCKED);
        EXPECT_SUCCESS(s2n_shutdown(server_conn, &server_blocked));
        EXPECT_SUCCESS(s2n_shutdown(client_conn, &client_blocked));

        /* Verify state after alert */
        EXPECT_SUCCESS(server_conn->close_notify_received);
        EXPECT_SUCCESS(client_conn->close_notify_received);

        /* Cleanup */
        EXPECT_SUCCESS(s2n_connection_free(server_conn));
        EXPECT_SUCCESS(s2n_connection_free(client_conn));
        EXPECT_SUCCESS(s2n_io_pair_close(&io_pair));
        EXPECT_SUCCESS(s2n_cert_chain_and_key_free(chain_and_key));
        EXPECT_SUCCESS(s2n_config_free(config));
    }

    /* Verify successful shutdown. Client and Server initiated. */
    {
        /* Setup connections */
        struct s2n_connection *client_conn, *server_conn;
        EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));

        /* Setup config */
        struct s2n_cert_chain_and_key *chain_and_key;
        EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&chain_and_key,
                S2N_DEFAULT_ECDSA_TEST_CERT_CHAIN, S2N_DEFAULT_ECDSA_TEST_PRIVATE_KEY));
        struct s2n_config *config;
        EXPECT_NOT_NULL(config = s2n_config_new());
        EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, "default_tls13"));
        EXPECT_SUCCESS(s2n_config_set_unsafe_for_testing(config));
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, chain_and_key));
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config));
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));

        /* Create nonblocking pipes */
        struct s2n_test_io_pair io_pair;
        EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
        EXPECT_SUCCESS(s2n_connection_set_io_pair(client_conn, &io_pair));
        EXPECT_SUCCESS(s2n_connection_set_io_pair(server_conn, &io_pair));

        /* Verify state prior to alert */
        EXPECT_FALSE(server_conn->close_notify_received);
        EXPECT_FALSE(client_conn->close_notify_received);

        /* Verify state when we dont call shutdown. Not a very interesting test case. */
        EXPECT_FALSE(server_conn->close_notify_received);
        EXPECT_FALSE(client_conn->close_notify_received);

        /* Cleanup */
        EXPECT_SUCCESS(s2n_connection_free(server_conn));
        EXPECT_SUCCESS(s2n_connection_free(client_conn));
        EXPECT_SUCCESS(s2n_io_pair_close(&io_pair));
        EXPECT_SUCCESS(s2n_cert_chain_and_key_free(chain_and_key));
        EXPECT_SUCCESS(s2n_config_free(config));
    }

    END_TEST();
}


