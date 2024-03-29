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

#include "tls/s2n_crypto.h"

#include "crypto/s2n_fips.h"
#include "s2n_test.h"
#include "testlib/s2n_testlib.h"

int main()
{
    BEGIN_TEST();

    DEFER_CLEANUP(struct s2n_cert_chain_and_key *ecdsa_chain_and_key = NULL,
            s2n_cert_chain_and_key_ptr_free);
    EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&ecdsa_chain_and_key,
            S2N_DEFAULT_ECDSA_TEST_CERT_CHAIN, S2N_DEFAULT_ECDSA_TEST_PRIVATE_KEY));

    /* Test s2n_connection_get_master_secret */
    {
        const uint8_t test_secret[S2N_TLS_SECRET_LEN] = {
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10,
            0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x20,
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10,
            0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xF8, 0xF9, 0xFF,
            0x88, 0x87, 0x86, 0x85, 0x84, 0x83, 0x82, 0x81
        };

        const uint8_t supported_versions[] = { S2N_SSLv3, S2N_TLS10, S2N_TLS11, S2N_TLS12 };

        /* s2n_connection_get_master_secret takes a constant connection, so our
         * tests can share the same connection.
         */
        DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_SERVER),
                s2n_connection_ptr_free);
        EXPECT_OK(s2n_skip_handshake(conn));
        EXPECT_MEMCPY_SUCCESS(conn->secrets.version.tls12.master_secret,
                test_secret, sizeof(test_secret));

        /* Test safety checks */
        {
            uint8_t output[S2N_TLS_SECRET_LEN] = { 0 };
            EXPECT_FAILURE_WITH_ERRNO(
                    s2n_connection_get_master_secret(conn, NULL, 0),
                    S2N_ERR_NULL);
            EXPECT_FAILURE_WITH_ERRNO(
                    s2n_connection_get_master_secret(NULL, output, 0),
                    S2N_ERR_NULL);
        };

        /* Test: successfully get master secret */
        {
            uint8_t output[S2N_TLS_SECRET_LEN] = { 0 };
            EXPECT_SUCCESS(s2n_connection_get_master_secret(conn, output, sizeof(output)));
            EXPECT_BYTEARRAY_EQUAL(test_secret, output, sizeof(output));
        };

        /* Test: TLS1.3 not supported */
        {
            uint8_t output[S2N_TLS_SECRET_LEN] = { 0 };

            conn->actual_protocol_version = S2N_TLS13;
            EXPECT_FAILURE_WITH_ERRNO(
                    s2n_connection_get_master_secret(conn, output, sizeof(output)),
                    S2N_ERR_INVALID_STATE);

            conn->actual_protocol_version = S2N_TLS12;
            EXPECT_SUCCESS(s2n_connection_get_master_secret(conn, output, sizeof(output)));
            EXPECT_BYTEARRAY_EQUAL(test_secret, output, sizeof(output));
        };

        /* Test: at least S2N_TLS_SECRET_LEN of output required */
        {
            uint8_t output[S2N_TLS_SECRET_LEN] = { 0 };

            /* Fail if insufficient memory */
            EXPECT_FAILURE_WITH_ERRNO(
                    s2n_connection_get_master_secret(conn, output, 0),
                    S2N_ERR_INSUFFICIENT_MEM_SIZE);
            EXPECT_FAILURE_WITH_ERRNO(
                    s2n_connection_get_master_secret(conn, output, 1),
                    S2N_ERR_INSUFFICIENT_MEM_SIZE);
            EXPECT_FAILURE_WITH_ERRNO(
                    s2n_connection_get_master_secret(conn, output, S2N_TLS_SECRET_LEN - 1),
                    S2N_ERR_INSUFFICIENT_MEM_SIZE);

            /* Succeed if exactly S2N_TLS_SECRET_LEN bytes */
            EXPECT_SUCCESS(s2n_connection_get_master_secret(conn, output, S2N_TLS_SECRET_LEN));
            EXPECT_BYTEARRAY_EQUAL(test_secret, output, sizeof(output));

            /* Succeed if more than S2N_TLS_SECRET_LEN bytes */
            EXPECT_SUCCESS(s2n_connection_get_master_secret(conn, output, S2N_TLS_SECRET_LEN + 1));
            EXPECT_BYTEARRAY_EQUAL(test_secret, output, sizeof(output));
        };

        /* Test: handshake must be complete */
        {
            uint8_t output[S2N_TLS_SECRET_LEN] = { 0 };

            conn->handshake.message_number = 0;
            EXPECT_FAILURE_WITH_ERRNO(
                    s2n_connection_get_master_secret(conn, output, sizeof(output)),
                    S2N_ERR_HANDSHAKE_NOT_COMPLETE);

            EXPECT_OK(s2n_skip_handshake(conn));
            EXPECT_SUCCESS(s2n_connection_get_master_secret(conn, output, sizeof(output)));
            EXPECT_BYTEARRAY_EQUAL(test_secret, output, sizeof(output));
        };

        /* Test: self-talk */
        for (size_t i = 0; i < s2n_array_len(supported_versions); i++) {
            const uint8_t version = supported_versions[i];

            /* See https://github.com/aws/s2n-tls/issues/4476
             * Retrieving the master secret won't vary between FIPS and non-FIPS,
             * so this testing limitation is not a concern.
             */
            if (s2n_is_in_fips_mode() && version == S2N_SSLv3) {
                continue;
            }

            DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
            EXPECT_NOT_NULL(config);
            EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, ecdsa_chain_and_key));
            EXPECT_SUCCESS(s2n_config_set_unsafe_for_testing(config));
            EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, "test_all"));

            DEFER_CLEANUP(struct s2n_connection *client = s2n_connection_new(S2N_CLIENT),
                    s2n_connection_ptr_free);
            EXPECT_NOT_NULL(client);
            EXPECT_SUCCESS(s2n_connection_set_config(client, config));
            client->client_protocol_version = version;

            DEFER_CLEANUP(struct s2n_connection *server = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            EXPECT_NOT_NULL(server);
            EXPECT_SUCCESS(s2n_connection_set_config(server, config));
            /* Set server master secret to known value to ensure overridden later */
            memset(server->secrets.version.tls12.master_secret, 1, S2N_TLS_SECRET_LEN);

            struct s2n_test_io_pair io_pair = { 0 };
            EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
            EXPECT_SUCCESS(s2n_connections_set_io_pair(client, server, &io_pair));
            EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server, client));
            EXPECT_EQUAL(server->actual_protocol_version, version);

            /* server output matches master secret */
            uint8_t server_output[S2N_TLS_SECRET_LEN] = { 0 };
            EXPECT_SUCCESS(s2n_connection_get_master_secret(server,
                    server_output, sizeof(server_output)));
            EXPECT_BYTEARRAY_EQUAL(server->secrets.version.tls12.master_secret,
                    server_output, sizeof(server_output));

            /* client output matches master secret */
            uint8_t client_output[S2N_TLS_SECRET_LEN] = { 0 };
            EXPECT_SUCCESS(s2n_connection_get_master_secret(client,
                    client_output, sizeof(client_output)));
            EXPECT_BYTEARRAY_EQUAL(client->secrets.version.tls12.master_secret,
                    client_output, sizeof(client_output));

            /* client and server output match */
            EXPECT_BYTEARRAY_EQUAL(server_output, client_output, sizeof(client_output));
        };
    };

    END_TEST();
}
