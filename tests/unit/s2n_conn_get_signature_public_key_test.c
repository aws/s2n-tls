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
#include "crypto/s2n_certificate.h"
#include "crypto/s2n_mldsa.h"
#include "s2n_test.h"
#include "testlib/s2n_testlib.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_tls.h"
#include "utils/s2n_random.h"

/* Maximum buffer size for public key string output */
#define S2N_PUBLIC_KEY_STR_MAX_SIZE 32

int main(int argc, char **argv)
{
    BEGIN_TEST();

    /* Test: NULL connection returns S2N_FAILURE with S2N_ERR_NULL */
    {
        char output[S2N_PUBLIC_KEY_STR_MAX_SIZE] = { 0 };
        uint32_t output_size = sizeof(output);

        EXPECT_FAILURE_WITH_ERRNO(
                s2n_conn_get_signature_public_key(NULL, S2N_SERVER, output, &output_size),
                S2N_ERR_NULL);
    };

    /* Test: NULL output buffer returns S2N_FAILURE with S2N_ERR_NULL */
    {
        struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT);
        EXPECT_NOT_NULL(conn);

        uint32_t output_size = S2N_PUBLIC_KEY_STR_MAX_SIZE;

        EXPECT_FAILURE_WITH_ERRNO(
                s2n_conn_get_signature_public_key(conn, S2N_SERVER, NULL, &output_size),
                S2N_ERR_NULL);

        EXPECT_SUCCESS(s2n_connection_free(conn));
    };

    /* Test: NULL output_size returns S2N_FAILURE with S2N_ERR_NULL */
    {
        struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT);
        EXPECT_NOT_NULL(conn);

        char output[S2N_PUBLIC_KEY_STR_MAX_SIZE] = { 0 };

        EXPECT_FAILURE_WITH_ERRNO(
                s2n_conn_get_signature_public_key(conn, S2N_SERVER, output, NULL),
                S2N_ERR_NULL);

        EXPECT_SUCCESS(s2n_connection_free(conn));
    };

    /* Test: Various certificate types return correct public key strings */
    {
        struct {
            const char *cert_type;
            const char *cert_sig;
            const char *cert_size;
            const char *cert_digest;
            const char *expected_output;
        } test_cases[] = {
            { .cert_type = "rsae", .cert_sig = "pkcs", .cert_size = "2048", .cert_digest = "sha256", .expected_output = "rsa_2048" },
            { .cert_type = "rsae", .cert_sig = "pkcs", .cert_size = "3072", .cert_digest = "sha256", .expected_output = "rsa_3072" },
            { .cert_type = "rsae", .cert_sig = "pkcs", .cert_size = "4096", .cert_digest = "sha384", .expected_output = "rsa_4096" },
            { .cert_type = "ec", .cert_sig = "ecdsa", .cert_size = "p256", .cert_digest = "sha256", .expected_output = "ecdsa_secp256r1" },
            { .cert_type = "ec", .cert_sig = "ecdsa", .cert_size = "p384", .cert_digest = "sha384", .expected_output = "ecdsa_secp384r1" },
            { .cert_type = "ec", .cert_sig = "ecdsa", .cert_size = "p521", .cert_digest = "sha512", .expected_output = "ecdsa_secp521r1" },
        };

        for (size_t i = 0; i < s2n_array_len(test_cases); i++) {
            DEFER_CLEANUP(struct s2n_cert_chain_and_key *chain_and_key = NULL,
                    s2n_cert_chain_and_key_ptr_free);
            EXPECT_SUCCESS(s2n_test_cert_permutation_load_server_chain(&chain_and_key,
                    test_cases[i].cert_type, test_cases[i].cert_sig,
                    test_cases[i].cert_size, test_cases[i].cert_digest));

            char ca_path[S2N_MAX_TEST_PEM_PATH_LENGTH] = { 0 };
            EXPECT_SUCCESS(s2n_test_cert_permutation_get_ca_path(ca_path,
                    test_cases[i].cert_type, test_cases[i].cert_sig,
                    test_cases[i].cert_size, test_cases[i].cert_digest));

            DEFER_CLEANUP(struct s2n_config *server_config = s2n_config_new(), s2n_config_ptr_free);
            EXPECT_NOT_NULL(server_config);
            EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(server_config, chain_and_key));
            EXPECT_SUCCESS(s2n_config_set_cipher_preferences(server_config, "default_tls13"));

            DEFER_CLEANUP(struct s2n_config *client_config = s2n_config_new(), s2n_config_ptr_free);
            EXPECT_NOT_NULL(client_config);
            EXPECT_SUCCESS(s2n_config_set_cipher_preferences(client_config, "default_tls13"));
            EXPECT_SUCCESS(s2n_config_set_verification_ca_location(client_config, ca_path, NULL));

            DEFER_CLEANUP(struct s2n_connection *client = s2n_connection_new(S2N_CLIENT),
                    s2n_connection_ptr_free);
            EXPECT_NOT_NULL(client);
            EXPECT_SUCCESS(s2n_connection_set_config(client, client_config));
            EXPECT_SUCCESS(s2n_set_server_name(client, "localhost"));

            DEFER_CLEANUP(struct s2n_connection *server = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            EXPECT_NOT_NULL(server);
            EXPECT_SUCCESS(s2n_connection_set_config(server, server_config));

            DEFER_CLEANUP(struct s2n_test_io_stuffer_pair io_pair = { 0 }, s2n_io_stuffer_pair_free);
            EXPECT_OK(s2n_io_stuffer_pair_init(&io_pair));
            EXPECT_OK(s2n_connections_set_io_stuffer_pair(client, server, &io_pair));

            EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server, client));

            char output[S2N_PUBLIC_KEY_STR_MAX_SIZE] = { 0 };
            uint32_t output_size = sizeof(output);

            EXPECT_SUCCESS(s2n_conn_get_signature_public_key(client, S2N_SERVER, output, &output_size));
            EXPECT_STRING_EQUAL(output, test_cases[i].expected_output);
        }
    };

    /* Test: ML-DSA certificates return correct public key strings */
    if (s2n_is_tls13_fully_supported() && s2n_mldsa_is_supported()) {
        struct {
            const char *cert_path;
            const char *key_path;
            const char *expected_output;
        } mldsa_test_cases[] = {
            { .cert_path = "../pems/mldsa/ML-DSA-44.crt", .key_path = "../pems/mldsa/ML-DSA-44-seed.priv", .expected_output = "mldsa44" },
            { .cert_path = "../pems/mldsa/ML-DSA-65.crt", .key_path = "../pems/mldsa/ML-DSA-65-seed.priv", .expected_output = "mldsa65" },
            { .cert_path = "../pems/mldsa/ML-DSA-87.crt", .key_path = "../pems/mldsa/ML-DSA-87-seed.priv", .expected_output = "mldsa87" },
        };

        for (size_t i = 0; i < s2n_array_len(mldsa_test_cases); i++) {
            DEFER_CLEANUP(struct s2n_cert_chain_and_key *chain_and_key = NULL,
                    s2n_cert_chain_and_key_ptr_free);
            EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&chain_and_key,
                    mldsa_test_cases[i].cert_path, mldsa_test_cases[i].key_path));

            DEFER_CLEANUP(struct s2n_config *server_config = s2n_config_new(), s2n_config_ptr_free);
            EXPECT_NOT_NULL(server_config);
            EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(server_config, chain_and_key));
            EXPECT_SUCCESS(s2n_config_set_cipher_preferences(server_config, "test_all_tls13"));

            DEFER_CLEANUP(struct s2n_config *client_config = s2n_config_new(), s2n_config_ptr_free);
            EXPECT_NOT_NULL(client_config);
            EXPECT_SUCCESS(s2n_config_set_cipher_preferences(client_config, "test_all_tls13"));
            EXPECT_SUCCESS(s2n_config_set_verification_ca_location(client_config,
                    mldsa_test_cases[i].cert_path, NULL));

            DEFER_CLEANUP(struct s2n_connection *client = s2n_connection_new(S2N_CLIENT),
                    s2n_connection_ptr_free);
            EXPECT_NOT_NULL(client);
            EXPECT_SUCCESS(s2n_connection_set_config(client, client_config));
            EXPECT_SUCCESS(s2n_set_server_name(client, "LAMPS WG"));

            DEFER_CLEANUP(struct s2n_connection *server = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            EXPECT_NOT_NULL(server);
            EXPECT_SUCCESS(s2n_connection_set_config(server, server_config));

            DEFER_CLEANUP(struct s2n_test_io_stuffer_pair io_pair = { 0 }, s2n_io_stuffer_pair_free);
            EXPECT_OK(s2n_io_stuffer_pair_init(&io_pair));
            EXPECT_OK(s2n_connections_set_io_stuffer_pair(client, server, &io_pair));

            EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server, client));

            char output[S2N_PUBLIC_KEY_STR_MAX_SIZE] = { 0 };
            uint32_t output_size = sizeof(output);

            EXPECT_SUCCESS(s2n_conn_get_signature_public_key(client, S2N_SERVER, output, &output_size));
            EXPECT_STRING_EQUAL(output, mldsa_test_cases[i].expected_output);
        }
    };

    /* Test: Buffer size handling and missing client certificate */
    {
        /* Set up a handshake with an RSA 2048 cert (output = "rsa_2048", 9 bytes with null) */
        DEFER_CLEANUP(struct s2n_cert_chain_and_key *chain_and_key = NULL,
                s2n_cert_chain_and_key_ptr_free);
        EXPECT_SUCCESS(s2n_test_cert_permutation_load_server_chain(&chain_and_key,
                "rsae", "pkcs", "2048", "sha256"));

        char ca_path[S2N_MAX_TEST_PEM_PATH_LENGTH] = { 0 };
        EXPECT_SUCCESS(s2n_test_cert_permutation_get_ca_path(ca_path, "rsae", "pkcs", "2048", "sha256"));

        DEFER_CLEANUP(struct s2n_config *server_config = s2n_config_new(), s2n_config_ptr_free);
        EXPECT_NOT_NULL(server_config);
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(server_config, chain_and_key));
        EXPECT_SUCCESS(s2n_config_set_cipher_preferences(server_config, "default_tls13"));

        DEFER_CLEANUP(struct s2n_config *client_config = s2n_config_new(), s2n_config_ptr_free);
        EXPECT_NOT_NULL(client_config);
        EXPECT_SUCCESS(s2n_config_set_cipher_preferences(client_config, "default_tls13"));
        EXPECT_SUCCESS(s2n_config_set_verification_ca_location(client_config, ca_path, NULL));

        DEFER_CLEANUP(struct s2n_connection *client = s2n_connection_new(S2N_CLIENT),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(client);
        EXPECT_SUCCESS(s2n_connection_set_config(client, client_config));
        EXPECT_SUCCESS(s2n_set_server_name(client, "localhost"));

        DEFER_CLEANUP(struct s2n_connection *server = s2n_connection_new(S2N_SERVER),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(server);
        EXPECT_SUCCESS(s2n_connection_set_config(server, server_config));

        DEFER_CLEANUP(struct s2n_test_io_stuffer_pair io_pair = { 0 }, s2n_io_stuffer_pair_free);
        EXPECT_OK(s2n_io_stuffer_pair_init(&io_pair));
        EXPECT_OK(s2n_connections_set_io_stuffer_pair(client, server, &io_pair));

        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server, client));

        /* "rsa_2048" = 8 chars + null = 9 bytes required */
        const uint32_t required_size = strlen("rsa_2048") + 1;

        /* Test: Buffer too small returns failure and sets required size */
        {
            char output[S2N_PUBLIC_KEY_STR_MAX_SIZE] = { 0 };
            uint32_t output_size = 4; /* Too small for "rsa_2048\0" */

            EXPECT_FAILURE_WITH_ERRNO(
                    s2n_conn_get_signature_public_key(client, S2N_SERVER, output, &output_size),
                    S2N_ERR_INSUFFICIENT_MEM_SIZE);
            EXPECT_EQUAL(output_size, required_size);
        };

        /* Test: Exact buffer size succeeds */
        {
            char output[S2N_PUBLIC_KEY_STR_MAX_SIZE] = { 0 };
            uint32_t output_size = required_size;

            EXPECT_SUCCESS(s2n_conn_get_signature_public_key(client, S2N_SERVER, output, &output_size));
            EXPECT_STRING_EQUAL(output, "rsa_2048");
            EXPECT_EQUAL(output_size, required_size);
        };

        /* Test: Larger buffer succeeds */
        {
            char output[S2N_PUBLIC_KEY_STR_MAX_SIZE] = { 0 };
            uint32_t output_size = sizeof(output);

            EXPECT_SUCCESS(s2n_conn_get_signature_public_key(client, S2N_SERVER, output, &output_size));
            EXPECT_STRING_EQUAL(output, "rsa_2048");
            EXPECT_EQUAL(output_size, required_size);
        };

        /* Test: Missing client certificate returns failure
         * No client auth was configured, so requesting client cert should fail */
        {
            char output[S2N_PUBLIC_KEY_STR_MAX_SIZE] = { 0 };
            uint32_t output_size = sizeof(output);

            EXPECT_FAILURE(s2n_conn_get_signature_public_key(server, S2N_CLIENT, output, &output_size));
        };
    };

    /* Test: Mode parameter selects correct certificate */
    {
        /* Use different cert types for server (RSA 2048) and client (ECDSA P256)
         * so we can distinguish which cert the API returns */
        DEFER_CLEANUP(struct s2n_cert_chain_and_key *server_chain = NULL,
                s2n_cert_chain_and_key_ptr_free);
        EXPECT_SUCCESS(s2n_test_cert_permutation_load_server_chain(&server_chain,
                "rsae", "pkcs", "2048", "sha256"));

        DEFER_CLEANUP(struct s2n_cert_chain_and_key *client_chain = NULL,
                s2n_cert_chain_and_key_ptr_free);
        EXPECT_SUCCESS(s2n_test_cert_permutation_load_server_chain(&client_chain,
                "ec", "ecdsa", "p256", "sha256"));

        char server_ca_path[S2N_MAX_TEST_PEM_PATH_LENGTH] = { 0 };
        EXPECT_SUCCESS(s2n_test_cert_permutation_get_ca_path(server_ca_path, "rsae", "pkcs", "2048", "sha256"));

        char client_ca_path[S2N_MAX_TEST_PEM_PATH_LENGTH] = { 0 };
        EXPECT_SUCCESS(s2n_test_cert_permutation_get_ca_path(client_ca_path, "ec", "ecdsa", "p256", "sha256"));

        /* Server config: RSA cert, trusts client's ECDSA CA, requires client auth */
        DEFER_CLEANUP(struct s2n_config *server_config = s2n_config_new(), s2n_config_ptr_free);
        EXPECT_NOT_NULL(server_config);
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(server_config, server_chain));
        EXPECT_SUCCESS(s2n_config_set_cipher_preferences(server_config, "default_tls13"));
        EXPECT_SUCCESS(s2n_config_set_verification_ca_location(server_config, client_ca_path, NULL));
        EXPECT_SUCCESS(s2n_config_set_client_auth_type(server_config, S2N_CERT_AUTH_REQUIRED));

        /* Client config: ECDSA cert, trusts server's RSA CA, requires client auth */
        DEFER_CLEANUP(struct s2n_config *client_config = s2n_config_new(), s2n_config_ptr_free);
        EXPECT_NOT_NULL(client_config);
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(client_config, client_chain));
        EXPECT_SUCCESS(s2n_config_set_cipher_preferences(client_config, "default_tls13"));
        EXPECT_SUCCESS(s2n_config_set_verification_ca_location(client_config, server_ca_path, NULL));
        EXPECT_SUCCESS(s2n_config_set_client_auth_type(client_config, S2N_CERT_AUTH_REQUIRED));

        DEFER_CLEANUP(struct s2n_connection *client = s2n_connection_new(S2N_CLIENT),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(client);
        EXPECT_SUCCESS(s2n_connection_set_config(client, client_config));
        EXPECT_SUCCESS(s2n_set_server_name(client, "localhost"));

        DEFER_CLEANUP(struct s2n_connection *server = s2n_connection_new(S2N_SERVER),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(server);
        EXPECT_SUCCESS(s2n_connection_set_config(server, server_config));

        DEFER_CLEANUP(struct s2n_test_io_stuffer_pair io_pair = { 0 }, s2n_io_stuffer_pair_free);
        EXPECT_OK(s2n_io_stuffer_pair_init(&io_pair));
        EXPECT_OK(s2n_connections_set_io_stuffer_pair(client, server, &io_pair));

        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server, client));

        /* Test: S2N_SERVER mode on client returns server's RSA cert info */
        {
            char output[S2N_PUBLIC_KEY_STR_MAX_SIZE] = { 0 };
            uint32_t output_size = sizeof(output);

            EXPECT_SUCCESS(s2n_conn_get_signature_public_key(client, S2N_SERVER, output, &output_size));
            EXPECT_STRING_EQUAL(output, "rsa_2048");
        };

        /* Test: S2N_CLIENT mode on server returns client's ECDSA cert info */
        {
            char output[S2N_PUBLIC_KEY_STR_MAX_SIZE] = { 0 };
            uint32_t output_size = sizeof(output);

            EXPECT_SUCCESS(s2n_conn_get_signature_public_key(server, S2N_CLIENT, output, &output_size));
            EXPECT_STRING_EQUAL(output, "ecdsa_secp256r1");
        };

        /* Test: S2N_SERVER mode on server returns server's own RSA cert info */
        {
            char output[S2N_PUBLIC_KEY_STR_MAX_SIZE] = { 0 };
            uint32_t output_size = sizeof(output);

            EXPECT_SUCCESS(s2n_conn_get_signature_public_key(server, S2N_SERVER, output, &output_size));
            EXPECT_STRING_EQUAL(output, "rsa_2048");
        };
    };

    /* Property Test: RSA key format consistency
     * For any RSA or RSA-PSS certificate with key size N, output matches "rsa_<N>" */
    {
        int nids[] = { NID_rsaEncryption, NID_rsassaPss };

        for (size_t nid_idx = 0; nid_idx < s2n_array_len(nids); nid_idx++) {
            for (size_t i = 0; i < 100; i++) {
                uint64_t rand_val = 0;
                EXPECT_OK(s2n_public_random(15360, &rand_val));
                int key_bits = 1024 + (int) rand_val;

                struct s2n_cert_info info = {
                    .public_key_nid = nids[nid_idx],
                    .public_key_bits = key_bits,
                };

                char output[S2N_PUBLIC_KEY_STR_MAX_SIZE] = { 0 };
                uint32_t output_size = sizeof(output);
                uint32_t required_size = 0;

                EXPECT_OK(s2n_cert_info_format_public_key_string(&info, output, output_size, &required_size));

                /* Verify format matches "rsa_<N>" */
                char expected[S2N_PUBLIC_KEY_STR_MAX_SIZE] = { 0 };
                snprintf(expected, sizeof(expected), "rsa_%d", key_bits);
                EXPECT_STRING_EQUAL(output, expected);

                /* Property 5: output_size == strlen(output) + 1 */
                EXPECT_EQUAL(required_size, strlen(output) + 1);
            }
        }
    };

    END_TEST();
}
