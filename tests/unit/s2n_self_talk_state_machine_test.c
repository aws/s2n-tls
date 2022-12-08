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

int main(int argc, char **argv)
{
    BEGIN_TEST();

    if (s2n_is_tls13_fully_supported()) {

        /* Set up generic TLS13 config */
        DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
        EXPECT_NOT_NULL(config);
        EXPECT_SUCCESS(s2n_config_set_unsafe_for_testing(config));
        EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, "default_tls13"));
        struct s2n_cert_chain_and_key *chain_and_key = NULL;
        EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&chain_and_key, S2N_DEFAULT_TEST_CERT_CHAIN, S2N_DEFAULT_TEST_PRIVATE_KEY));
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, chain_and_key));

        /* Generic TLS12 config */
        DEFER_CLEANUP(struct s2n_config *tls12_config = s2n_config_new(), s2n_config_ptr_free);
        EXPECT_NOT_NULL(tls12_config);
        EXPECT_SUCCESS(s2n_config_set_unsafe_for_testing(tls12_config));
        EXPECT_SUCCESS(s2n_config_set_cipher_preferences(tls12_config, "default"));
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(tls12_config, chain_and_key));

        DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER), s2n_connection_ptr_free);
        EXPECT_NOT_NULL(server_conn);
        EXPECT_SUCCESS(s2n_connection_set_blinding(server_conn, S2N_SELF_SERVICE_BLINDING));

        DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT), s2n_connection_ptr_free);
        EXPECT_NOT_NULL(client_conn);
        EXPECT_SUCCESS(s2n_connection_set_blinding(client_conn, S2N_SELF_SERVICE_BLINDING));

        /* Create nonblocking pipes */
        struct s2n_test_io_pair io_pair;
        EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
        EXPECT_SUCCESS(s2n_connections_set_io_pair(client_conn, server_conn, &io_pair));

        /* A connection cannot switch to the TLS12 state machine midway through the handshake */
        {
            EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));
            EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config));

            /* Do handshake until the cert message is reached */
            EXPECT_OK(s2n_negotiate_test_server_and_client_until_message(server_conn, client_conn, SERVER_CERT));

            EXPECT_EQUAL(s2n_connection_get_actual_protocol_version(server_conn), S2N_TLS13);
            EXPECT_EQUAL(s2n_connection_get_actual_protocol_version(client_conn), S2N_TLS13);

            /* Alter which state machine the connection is using */
            server_conn->actual_protocol_version = S2N_TLS12;
            client_conn->actual_protocol_version = S2N_TLS12;

            EXPECT_FAILURE_WITH_ERRNO(s2n_negotiate_test_server_and_client(server_conn, client_conn), S2N_ERR_SAFETY);
        }

        /* A connection cannot switch to the TLS13 state machine midway through the handshake */
        {
            EXPECT_SUCCESS(s2n_connection_wipe(server_conn));
            EXPECT_SUCCESS(s2n_connection_wipe(client_conn));
            EXPECT_SUCCESS(s2n_connection_set_config(server_conn, tls12_config));
            EXPECT_SUCCESS(s2n_connection_set_config(client_conn, tls12_config));
            EXPECT_SUCCESS(s2n_connections_set_io_pair(client_conn, server_conn, &io_pair));

            /* Do handshake until the server hello message is reached */
            EXPECT_OK(s2n_negotiate_test_server_and_client_until_message(server_conn, client_conn, SERVER_HELLO));

            EXPECT_EQUAL(s2n_connection_get_actual_protocol_version(server_conn), S2N_TLS12);
            EXPECT_EQUAL(s2n_connection_get_actual_protocol_version(client_conn), S2N_TLS12);

            /* Alter which state machine the connection is using */
            server_conn->actual_protocol_version = S2N_TLS13;
            client_conn->actual_protocol_version = S2N_TLS13;

            EXPECT_FAILURE_WITH_ERRNO(s2n_negotiate_test_server_and_client(server_conn, client_conn), S2N_ERR_SAFETY);
        }

        /* A hello retry handshake cannot change state machines */
        {
            EXPECT_SUCCESS(s2n_connection_wipe(server_conn));
            EXPECT_SUCCESS(s2n_connection_wipe(client_conn));
            EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));
            EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config));
            EXPECT_SUCCESS(s2n_connections_set_io_pair(client_conn, server_conn, &io_pair));

            /* Force the HRR path */
            client_conn->security_policy_override = &security_policy_test_tls13_retry;

            /* Negotiate handshake until cert message */
            EXPECT_OK(s2n_negotiate_test_server_and_client_until_message(server_conn, client_conn, SERVER_CERT));

            EXPECT_EQUAL(s2n_connection_get_actual_protocol_version(server_conn), S2N_TLS13);
            EXPECT_EQUAL(s2n_connection_get_actual_protocol_version(client_conn), S2N_TLS13);

            EXPECT_TRUE(IS_HELLO_RETRY_HANDSHAKE(server_conn));
            EXPECT_TRUE(IS_HELLO_RETRY_HANDSHAKE(client_conn));

            /* Alter which state machine the connection is using */
            client_conn->actual_protocol_version = S2N_TLS12;
            server_conn->actual_protocol_version = S2N_TLS12;

            EXPECT_FAILURE_WITH_ERRNO(s2n_negotiate_test_server_and_client(server_conn, client_conn), S2N_ERR_SAFETY);
        }

        EXPECT_SUCCESS(s2n_cert_chain_and_key_free(chain_and_key));
    }
    END_TEST();
}
