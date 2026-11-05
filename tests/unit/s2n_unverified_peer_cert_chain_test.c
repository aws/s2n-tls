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
#include "tls/s2n_tls.h"

static uint8_t always_verify_host_fn(const char *host_name, size_t host_name_len, void *data)
{
    return true;
}

int main(int argc, char **argv)
{
    BEGIN_TEST();

    DEFER_CLEANUP(struct s2n_cert_chain_and_key *server_chain_and_key = NULL, s2n_cert_chain_and_key_ptr_free);
    EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&server_chain_and_key,
            S2N_DEFAULT_ECDSA_TEST_CERT_CHAIN, S2N_DEFAULT_ECDSA_TEST_PRIVATE_KEY));

    /* Test: NULL and invalid argument error cases */
    {
        DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT), s2n_connection_ptr_free);
        EXPECT_NOT_NULL(conn);

        DEFER_CLEANUP(struct s2n_cert_chain_and_key *chain = s2n_cert_chain_and_key_new(),
                s2n_cert_chain_and_key_ptr_free);
        EXPECT_NOT_NULL(chain);

        /* NULL conn */
        EXPECT_FAILURE_WITH_ERRNO(s2n_connection_get_unverified_peer_cert_chain(NULL, chain), S2N_ERR_NULL);

        /* NULL cert_chain_and_key */
        EXPECT_FAILURE_WITH_ERRNO(s2n_connection_get_unverified_peer_cert_chain(conn, NULL), S2N_ERR_NULL);

        /* Non-empty cert_chain_and_key should be rejected */
        {
            DEFER_CLEANUP(struct s2n_cert_chain_and_key *non_empty = NULL, s2n_cert_chain_and_key_ptr_free);
            EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&non_empty,
                    S2N_DEFAULT_ECDSA_TEST_CERT_CHAIN, S2N_DEFAULT_ECDSA_TEST_PRIVATE_KEY));
            EXPECT_FAILURE_WITH_ERRNO(s2n_connection_get_unverified_peer_cert_chain(conn, non_empty),
                    S2N_ERR_INVALID_ARGUMENT);
        }

        /* No cert received yet (validator has no certs) */
        EXPECT_FAILURE(s2n_connection_get_unverified_peer_cert_chain(conn, chain));
    };

    /* Test: Successful handshake - unverified chain matches validated chain */
    {
        DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT), s2n_connection_ptr_free);
        DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER), s2n_connection_ptr_free);
        EXPECT_NOT_NULL(client_conn);
        EXPECT_NOT_NULL(server_conn);

        struct s2n_test_io_pair io_pair = { 0 };
        EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));

        DEFER_CLEANUP(struct s2n_config *client_config = s2n_config_new(), s2n_config_ptr_free);
        EXPECT_NOT_NULL(client_config);
        EXPECT_SUCCESS(s2n_config_set_cipher_preferences(client_config, "test_all"));
        EXPECT_SUCCESS(s2n_config_set_verification_ca_location(client_config,
                S2N_DEFAULT_ECDSA_TEST_CERT_CHAIN, NULL));
        EXPECT_SUCCESS(s2n_config_set_verify_host_callback(client_config, always_verify_host_fn, NULL));

        DEFER_CLEANUP(struct s2n_config *server_config = s2n_config_new(), s2n_config_ptr_free);
        EXPECT_NOT_NULL(server_config);
        EXPECT_SUCCESS(s2n_config_set_cipher_preferences(server_config, "test_all"));
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(server_config, server_chain_and_key));

        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, client_config));
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, server_config));
        EXPECT_SUCCESS(s2n_connections_set_io_pair(client_conn, server_conn, &io_pair));

        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));

        /* get_unverified_peer_cert_chain should succeed after a successful handshake */
        DEFER_CLEANUP(struct s2n_cert_chain_and_key *unverified_chain = s2n_cert_chain_and_key_new(),
                s2n_cert_chain_and_key_ptr_free);
        EXPECT_NOT_NULL(unverified_chain);
        EXPECT_SUCCESS(s2n_connection_get_unverified_peer_cert_chain(client_conn, unverified_chain));

        uint32_t unverified_len = 0;
        EXPECT_SUCCESS(s2n_cert_chain_get_length(unverified_chain, &unverified_len));
        EXPECT_TRUE(unverified_len > 0);

        /* Also get the validated chain for comparison */
        DEFER_CLEANUP(struct s2n_cert_chain_and_key *validated_chain = s2n_cert_chain_and_key_new(),
                s2n_cert_chain_and_key_ptr_free);
        EXPECT_NOT_NULL(validated_chain);
        EXPECT_SUCCESS(s2n_connection_get_peer_cert_chain(client_conn, validated_chain));

        uint32_t validated_len = 0;
        EXPECT_SUCCESS(s2n_cert_chain_get_length(validated_chain, &validated_len));

        /* The unverified chain from wire should have at least as many certs as
         * what was sent. The validated chain may differ (OpenSSL trust path
         * resolution can reorder or add certs from the trust store), so we just
         * verify the leaf cert matches between the two.
         */
        EXPECT_TRUE(unverified_len > 0);

        struct s2n_cert *unverified_leaf = NULL;
        EXPECT_SUCCESS(s2n_cert_chain_get_cert(unverified_chain, &unverified_leaf, 0));
        EXPECT_NOT_NULL(unverified_leaf);

        struct s2n_cert *validated_leaf = NULL;
        EXPECT_SUCCESS(s2n_cert_chain_get_cert(validated_chain, &validated_leaf, 0));
        EXPECT_NOT_NULL(validated_leaf);

        const uint8_t *unverified_der = NULL;
        uint32_t unverified_der_len = 0;
        EXPECT_SUCCESS(s2n_cert_get_der(unverified_leaf, &unverified_der, &unverified_der_len));

        const uint8_t *validated_der = NULL;
        uint32_t validated_der_len = 0;
        EXPECT_SUCCESS(s2n_cert_get_der(validated_leaf, &validated_der, &validated_der_len));

        EXPECT_EQUAL(unverified_der_len, validated_der_len);
        EXPECT_BYTEARRAY_EQUAL(unverified_der, validated_der, unverified_der_len);

        EXPECT_SUCCESS(s2n_shutdown_test_server_and_client(server_conn, client_conn));
    };

    /* Test: Failed validation - unverified chain is still accessible */
    {
        DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT), s2n_connection_ptr_free);
        DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER), s2n_connection_ptr_free);
        EXPECT_NOT_NULL(client_conn);
        EXPECT_NOT_NULL(server_conn);

        struct s2n_test_io_pair io_pair = { 0 };
        EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));

        /* Client config trusts RSA cert but server sends ECDSA cert.
         * This ensures the cert chain IS parsed (read_cert_chain succeeds)
         * but validation fails (X509_verify_cert rejects the chain).
         */
        DEFER_CLEANUP(struct s2n_config *client_config = s2n_config_new(), s2n_config_ptr_free);
        EXPECT_NOT_NULL(client_config);
        EXPECT_SUCCESS(s2n_config_set_cipher_preferences(client_config, "test_all"));
        /* Trust a different CA than what the server uses */
        EXPECT_SUCCESS(s2n_config_set_verification_ca_location(client_config,
                S2N_DEFAULT_TEST_CERT_CHAIN, NULL));
        EXPECT_SUCCESS(s2n_config_set_verify_host_callback(client_config, always_verify_host_fn, NULL));

        DEFER_CLEANUP(struct s2n_config *server_config = s2n_config_new(), s2n_config_ptr_free);
        EXPECT_NOT_NULL(server_config);
        EXPECT_SUCCESS(s2n_config_set_cipher_preferences(server_config, "test_all"));
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(server_config, server_chain_and_key));

        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, client_config));
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, server_config));
        EXPECT_SUCCESS(s2n_connections_set_io_pair(client_conn, server_conn, &io_pair));

        /* Handshake should fail due to untrusted cert */
        EXPECT_FAILURE(s2n_negotiate_test_server_and_client(server_conn, client_conn));

        /* get_peer_cert_chain should fail (not validated) */
        {
            DEFER_CLEANUP(struct s2n_cert_chain_and_key *chain = s2n_cert_chain_and_key_new(),
                    s2n_cert_chain_and_key_ptr_free);
            EXPECT_NOT_NULL(chain);
            EXPECT_FAILURE_WITH_ERRNO(s2n_connection_get_peer_cert_chain(client_conn, chain),
                    S2N_ERR_CERT_NOT_VALIDATED);
        }

        /* But get_unverified_peer_cert_chain should succeed! This is the key use case. */
        {
            DEFER_CLEANUP(struct s2n_cert_chain_and_key *chain = s2n_cert_chain_and_key_new(),
                    s2n_cert_chain_and_key_ptr_free);
            EXPECT_NOT_NULL(chain);
            EXPECT_SUCCESS(s2n_connection_get_unverified_peer_cert_chain(client_conn, chain));

            uint32_t chain_len = 0;
            EXPECT_SUCCESS(s2n_cert_chain_get_length(chain, &chain_len));
            EXPECT_TRUE(chain_len > 0);

            /* Verify we can read the leaf cert DER data */
            struct s2n_cert *leaf = NULL;
            EXPECT_SUCCESS(s2n_cert_chain_get_cert(chain, &leaf, 0));
            EXPECT_NOT_NULL(leaf);

            const uint8_t *der = NULL;
            uint32_t der_len = 0;
            EXPECT_SUCCESS(s2n_cert_get_der(leaf, &der, &der_len));
            EXPECT_TRUE(der_len > 0);
        }
    };

    END_TEST();
}
