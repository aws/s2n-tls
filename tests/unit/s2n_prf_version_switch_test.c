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

/*
 * Verifies that a reused connection (wipe between handshakes) can switch between
 * TLS 1.3 and TLS 1.2 full handshakes without errors. This exercises the lazy
 * per-side allocation in prf_space: the ensure_tls12/ensure_tls13 helpers must
 * correctly free the other side's contexts before allocating the new side when
 * the protocol version changes between handshakes on the same connection.
 */

#include "s2n_test.h"
#include "testlib/s2n_testlib.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_tls.h"

int main(int argc, char **argv)
{
    BEGIN_TEST();

    if (!s2n_is_tls13_fully_supported()) {
        END_TEST();
    }

    /* TLS 1.3 config */
    struct s2n_config *tls13_config = s2n_config_new();
    EXPECT_NOT_NULL(tls13_config);
    EXPECT_SUCCESS(s2n_config_set_cipher_preferences(tls13_config, "default_tls13"));
    EXPECT_SUCCESS(s2n_config_set_unsafe_for_testing(tls13_config));
    struct s2n_cert_chain_and_key *tls13_chain = NULL;
    EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&tls13_chain,
            S2N_DEFAULT_ECDSA_TEST_CERT_CHAIN, S2N_DEFAULT_ECDSA_TEST_PRIVATE_KEY));
    EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(tls13_config, tls13_chain));

    /* TLS 1.2 config */
    struct s2n_config *tls12_config = s2n_config_new();
    EXPECT_NOT_NULL(tls12_config);
    EXPECT_SUCCESS(s2n_config_set_cipher_preferences(tls12_config, "test_all_tls12"));
    EXPECT_SUCCESS(s2n_config_set_unsafe_for_testing(tls12_config));
    struct s2n_cert_chain_and_key *tls12_chain = NULL;
    EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&tls12_chain,
            S2N_DEFAULT_TEST_CERT_CHAIN, S2N_DEFAULT_TEST_PRIVATE_KEY));
    EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(tls12_config, tls12_chain));

    /* TLS 1.3 → wipe → TLS 1.2 on the same connection */
    {
        struct s2n_connection *client = s2n_connection_new(S2N_CLIENT);
        struct s2n_connection *server = s2n_connection_new(S2N_SERVER);
        EXPECT_NOT_NULL(client);
        EXPECT_NOT_NULL(server);

        /* First handshake: TLS 1.3 */
        EXPECT_SUCCESS(s2n_connection_set_config(client, tls13_config));
        EXPECT_SUCCESS(s2n_connection_set_config(server, tls13_config));

        struct s2n_test_io_pair io_pair = { 0 };
        EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
        EXPECT_SUCCESS(s2n_connections_set_io_pair(client, server, &io_pair));

        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server, client));
        EXPECT_EQUAL(client->actual_protocol_version, S2N_TLS13);
        EXPECT_EQUAL(server->actual_protocol_version, S2N_TLS13);

        EXPECT_SUCCESS(s2n_shutdown_test_server_and_client(server, client));

        /* Wipe and reconfigure for TLS 1.2 */
        EXPECT_SUCCESS(s2n_connection_wipe(client));
        EXPECT_SUCCESS(s2n_connection_wipe(server));
        EXPECT_SUCCESS(s2n_connection_set_config(client, tls12_config));
        EXPECT_SUCCESS(s2n_connection_set_config(server, tls12_config));

        EXPECT_SUCCESS(s2n_io_pair_close(&io_pair));
        EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
        EXPECT_SUCCESS(s2n_connections_set_io_pair(client, server, &io_pair));

        /* Second handshake: TLS 1.2 (full, not resumed) */
        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server, client));
        EXPECT_EQUAL(client->actual_protocol_version, S2N_TLS12);
        EXPECT_EQUAL(server->actual_protocol_version, S2N_TLS12);

        EXPECT_SUCCESS(s2n_shutdown_test_server_and_client(server, client));
        EXPECT_SUCCESS(s2n_io_pair_close(&io_pair));
        EXPECT_SUCCESS(s2n_connection_free(client));
        EXPECT_SUCCESS(s2n_connection_free(server));
    };

    /* TLS 1.2 → wipe → TLS 1.3 on the same connection */
    {
        struct s2n_connection *client = s2n_connection_new(S2N_CLIENT);
        struct s2n_connection *server = s2n_connection_new(S2N_SERVER);
        EXPECT_NOT_NULL(client);
        EXPECT_NOT_NULL(server);

        /* First handshake: TLS 1.2 */
        EXPECT_SUCCESS(s2n_connection_set_config(client, tls12_config));
        EXPECT_SUCCESS(s2n_connection_set_config(server, tls12_config));

        struct s2n_test_io_pair io_pair = { 0 };
        EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
        EXPECT_SUCCESS(s2n_connections_set_io_pair(client, server, &io_pair));

        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server, client));
        EXPECT_EQUAL(client->actual_protocol_version, S2N_TLS12);
        EXPECT_EQUAL(server->actual_protocol_version, S2N_TLS12);

        EXPECT_SUCCESS(s2n_shutdown_test_server_and_client(server, client));

        /* Wipe and reconfigure for TLS 1.3 */
        EXPECT_SUCCESS(s2n_connection_wipe(client));
        EXPECT_SUCCESS(s2n_connection_wipe(server));
        EXPECT_SUCCESS(s2n_connection_set_config(client, tls13_config));
        EXPECT_SUCCESS(s2n_connection_set_config(server, tls13_config));

        EXPECT_SUCCESS(s2n_io_pair_close(&io_pair));
        EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
        EXPECT_SUCCESS(s2n_connections_set_io_pair(client, server, &io_pair));

        /* Second handshake: TLS 1.3 (full, not resumed) */
        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server, client));
        EXPECT_EQUAL(client->actual_protocol_version, S2N_TLS13);
        EXPECT_EQUAL(server->actual_protocol_version, S2N_TLS13);

        EXPECT_SUCCESS(s2n_shutdown_test_server_and_client(server, client));
        EXPECT_SUCCESS(s2n_io_pair_close(&io_pair));
        EXPECT_SUCCESS(s2n_connection_free(client));
        EXPECT_SUCCESS(s2n_connection_free(server));
    };

    EXPECT_SUCCESS(s2n_cert_chain_and_key_free(tls13_chain));
    EXPECT_SUCCESS(s2n_cert_chain_and_key_free(tls12_chain));
    EXPECT_SUCCESS(s2n_config_free(tls13_config));
    EXPECT_SUCCESS(s2n_config_free(tls12_config));

    END_TEST();
}
