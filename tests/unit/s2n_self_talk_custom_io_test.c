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

#include <stdint.h>

#include "api/s2n.h"
#include "s2n_test.h"
#include "testlib/s2n_testlib.h"
#include "tls/s2n_connection.h"

int main(int argc, char **argv)
{
    BEGIN_TEST();

    /**
     * This test verifies that a server using custom I/O callbacks
     * can successfully negotiate and shutdown a TLS connection, and that
     * s2n_connection_use_corked_io() correctly fails when custom I/O is set.
     */
    {
        DEFER_CLEANUP(struct s2n_config *server_config = s2n_config_new(),
                s2n_config_ptr_free);
        EXPECT_OK(s2n_config_set_tls12_security_policy(server_config));
        DEFER_CLEANUP(struct s2n_cert_chain_and_key *chain_and_key = s2n_cert_chain_and_key_new(),
                s2n_cert_chain_and_key_ptr_free);
        char *cert_chain_pem = NULL;
        char *private_key_pem = NULL;
        char *dhparams_pem = NULL;
        EXPECT_NOT_NULL(cert_chain_pem = malloc(S2N_MAX_TEST_PEM_SIZE));
        EXPECT_NOT_NULL(private_key_pem = malloc(S2N_MAX_TEST_PEM_SIZE));
        EXPECT_NOT_NULL(dhparams_pem = malloc(S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_CERT_CHAIN, cert_chain_pem, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_PRIVATE_KEY, private_key_pem, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_DHPARAMS, dhparams_pem, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(s2n_cert_chain_and_key_load_pem(chain_and_key, cert_chain_pem, private_key_pem));
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(server_config, chain_and_key));
        EXPECT_SUCCESS(s2n_config_add_dhparams(server_config, dhparams_pem));

        DEFER_CLEANUP(struct s2n_config *client_config = s2n_config_new(),
                s2n_config_ptr_free);
        EXPECT_OK(s2n_config_set_tls12_security_policy(client_config));
        EXPECT_SUCCESS(s2n_config_disable_x509_verification(client_config));

        DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER),
                s2n_connection_ptr_free);
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, server_config));

        DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT),
                s2n_connection_ptr_free);
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, client_config));

        /* Set up the server with custom I/O callbacks (stuffers) */
        DEFER_CLEANUP(struct s2n_test_io_stuffer_pair io_pair = { 0 }, s2n_io_stuffer_pair_free);
        EXPECT_OK(s2n_io_stuffer_pair_init(&io_pair));
        EXPECT_OK(s2n_connections_set_io_stuffer_pair(client_conn, server_conn, &io_pair));

        /* Corked IO should fail because the server is using custom I/O callbacks.
         * s2n_connection_use_corked_io is not available on Windows.
         */
#ifndef _WIN32
        EXPECT_FAILURE(s2n_connection_use_corked_io(server_conn));
#endif

        /* Negotiate the handshake */
        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));

        /* Shutdown after negotiating */
        EXPECT_SUCCESS(s2n_shutdown_test_server_and_client(server_conn, client_conn));

        free(cert_chain_pem);
        free(private_key_pem);
        free(dhparams_pem);
    };

    /**
     * Clients and servers can utilize both custom IO and default IO for their sending and receiving.
     * This test uses s2n_connection_set_write_fd/s2n_connection_set_read_fd which are not
     * available on Windows.
     */
#ifndef _WIN32
    {
        /* Setup connections */
        struct s2n_connection *client_conn = NULL;
        struct s2n_connection *server_conn = NULL;
        EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));

        /* Setup config */
        struct s2n_config *config_with_certs = NULL;
        EXPECT_NOT_NULL(config_with_certs = s2n_config_new());
        EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config_with_certs, "default_tls13"));
        EXPECT_SUCCESS(s2n_config_set_unsafe_for_testing(config_with_certs));
        struct s2n_cert_chain_and_key *chain_and_key = NULL;
        EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&chain_and_key, S2N_DEFAULT_ECDSA_TEST_CERT_CHAIN,
                S2N_DEFAULT_ECDSA_TEST_PRIVATE_KEY));
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config_with_certs, chain_and_key));

        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config_with_certs));
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config_with_certs));

        /* Create nonblocking pipes */
        struct s2n_test_io_pair io_pair = { 0 };
        EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));

        /* Server writes to fd and client reads from fd */
        EXPECT_SUCCESS(s2n_connection_set_write_fd(server_conn, io_pair.server));
        EXPECT_SUCCESS(s2n_connection_set_read_fd(client_conn, io_pair.client));

        DEFER_CLEANUP(struct s2n_stuffer stuffer = { 0 }, s2n_stuffer_free);
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&stuffer, S2N_DEFAULT_RECORD_LENGTH));

        /* Client writes to stuffer and server reads from stuffer */
        EXPECT_SUCCESS(s2n_connection_set_send_io_stuffer(&stuffer, client_conn));
        EXPECT_SUCCESS(s2n_connection_set_recv_io_stuffer(&stuffer, server_conn));

        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));

        /* Clean-up */
        EXPECT_SUCCESS(s2n_connection_free(server_conn));
        EXPECT_SUCCESS(s2n_connection_free(client_conn));
        EXPECT_SUCCESS(s2n_config_free(config_with_certs));
        EXPECT_SUCCESS(s2n_io_pair_close(&io_pair));
        EXPECT_SUCCESS(s2n_cert_chain_and_key_free(chain_and_key));
    };
#endif

    END_TEST();
}
