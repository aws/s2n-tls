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
#include "tls/s2n_connection.h"
#include "tls/s2n_handshake.h"
#include "utils/s2n_safety.h"

#define TEST_DATA_SIZE 8

int main(int argc, char **argv)
{
    const char *protocols[] = { "http/1.1", "spdy/3.1", "h2" };
    const char *mismatch_protocols[] = { "spdy/2" };

    BEGIN_TEST();

    DEFER_CLEANUP(struct s2n_config *server_config = s2n_config_new(), s2n_config_ptr_free);
    EXPECT_NOT_NULL(server_config);
    EXPECT_SUCCESS(s2n_config_set_protocol_preferences(server_config, protocols,
            s2n_array_len(protocols)));
    EXPECT_SUCCESS(s2n_config_set_cipher_preferences(server_config, "default"));

    DEFER_CLEANUP(struct s2n_cert_chain_and_key *chain_and_key = NULL,
            s2n_cert_chain_and_key_ptr_free);
    EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&chain_and_key, S2N_DEFAULT_TEST_CERT_CHAIN,
            S2N_DEFAULT_TEST_PRIVATE_KEY));
    EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(server_config, chain_and_key));

    struct {
        int client_protocol_count;
        const char *const *client_protocols;
        const char *expected_protocol;
    } test_cases[] = {
        /* Test no client ALPN request */
        {
                .client_protocol_count = 0,
                .client_protocols = NULL,
                .expected_protocol = NULL,
        },
        /* Test a matching ALPN request */
        {
                .client_protocol_count = s2n_array_len(protocols),
                .client_protocols = protocols,
                .expected_protocol = protocols[0],
        },
        /* Test a lower preferred matching ALPN request */
        {
                .client_protocol_count = 1,
                .client_protocols = &protocols[1],
                .expected_protocol = protocols[1],
        },
        /* Test a non-matching ALPN request */
        {
                .client_protocol_count = 1,
                .client_protocols = mismatch_protocols,
                .expected_protocol = NULL,
        },
    };

    for (size_t i = 0; i < s2n_array_len(test_cases); i++) {
        DEFER_CLEANUP(struct s2n_config *client_config = s2n_config_new(), s2n_config_ptr_free);
        EXPECT_NOT_NULL(client_config);
        EXPECT_SUCCESS(s2n_config_set_protocol_preferences(client_config,
                test_cases[i].client_protocols, test_cases[i].client_protocol_count));
        EXPECT_SUCCESS(s2n_config_disable_x509_verification(client_config));

        DEFER_CLEANUP(struct s2n_connection *client = s2n_connection_new(S2N_CLIENT),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(client);
        EXPECT_SUCCESS(s2n_connection_set_config(client, client_config));

        DEFER_CLEANUP(struct s2n_connection *server = s2n_connection_new(S2N_SERVER),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(server);
        EXPECT_SUCCESS(s2n_connection_set_config(server, server_config));

        DEFER_CLEANUP(struct s2n_test_io_stuffer_pair io_pair = { 0 }, s2n_io_stuffer_pair_free);
        EXPECT_OK(s2n_io_stuffer_pair_init(&io_pair));
        EXPECT_OK(s2n_connections_set_io_stuffer_pair(client, server, &io_pair));

        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server, client));

        if (test_cases[i].expected_protocol == NULL) {
            EXPECT_NULL(s2n_get_application_protocol(server));
        } else {
            EXPECT_STRING_EQUAL(s2n_get_application_protocol(server),
                    test_cases[i].expected_protocol);
        }

        /* application data can be sent */
        s2n_blocked_status blocked = S2N_NOT_BLOCKED;
        uint8_t data_send[TEST_DATA_SIZE] = { 3, 1, 4, 1, 5, 9, 2, 6 };
        uint8_t data_recv[TEST_DATA_SIZE] = { 0 };
        EXPECT_EQUAL(s2n_send(client, data_send, sizeof(data_send), &blocked), sizeof(data_send));
        EXPECT_EQUAL(s2n_recv(server, data_recv, sizeof(data_recv), &blocked), sizeof(data_recv));
        EXPECT_BYTEARRAY_EQUAL(data_send, data_recv, sizeof(data_send));
    }

    /* Test a connection level application protocol */
    {
        DEFER_CLEANUP(struct s2n_config *client_config = s2n_config_new(), s2n_config_ptr_free);
        EXPECT_NOT_NULL(client_config);
        EXPECT_SUCCESS(s2n_config_set_protocol_preferences(client_config, protocols,
                s2n_array_len(protocols)));
        EXPECT_SUCCESS(s2n_config_disable_x509_verification(client_config));

        DEFER_CLEANUP(struct s2n_connection *client = s2n_connection_new(S2N_CLIENT),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(client);
        EXPECT_SUCCESS(s2n_connection_set_config(client, client_config));

        DEFER_CLEANUP(struct s2n_connection *server = s2n_connection_new(S2N_SERVER),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(server);
        EXPECT_SUCCESS(s2n_connection_set_config(server, server_config));

        /* override the server (connection) preferences to only contain h2 */
        EXPECT_SUCCESS(s2n_connection_set_protocol_preferences(server, &protocols[2], 1));

        DEFER_CLEANUP(struct s2n_test_io_stuffer_pair io_pair = { 0 }, s2n_io_stuffer_pair_free);
        EXPECT_OK(s2n_io_stuffer_pair_init(&io_pair));
        EXPECT_OK(s2n_connections_set_io_stuffer_pair(client, server, &io_pair));

        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server, client));

        /* despite being least preferred for the server_config and client, the
         * connection override correctly caused h2 to be negotiated 
         */
        EXPECT_STRING_EQUAL(s2n_get_application_protocol(server), protocols[2]);
    }

    END_TEST();

    return 0;
}
