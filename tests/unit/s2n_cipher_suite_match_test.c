/*
 * Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

#include <string.h>

#include "crypto/s2n_ecc_evp.h"
#include "tls/s2n_cipher_suites.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_cipher_preferences.h"

int main(int argc, char **argv)
{
    BEGIN_TEST();
    {
        struct s2n_connection *conn;
        uint8_t wire[2];
        int count;
        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));

        char *cert_chain;
        char *private_key;
        EXPECT_NOT_NULL(cert_chain = malloc(S2N_MAX_TEST_PEM_SIZE));
        EXPECT_NOT_NULL(private_key = malloc(S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_CERT_CHAIN, cert_chain, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_PRIVATE_KEY, private_key, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key(conn->config, cert_chain, private_key));

        count = 0;
        for (int i = 0; i < 0xffff; i++) {
            wire[0] = (i >> 8);
            wire[1] = i & 0xff;

            if (s2n_set_cipher_as_client(conn, wire) == 0) {
                count++;
            }
        }

        EXPECT_EQUAL(count, S2N_CIPHER_SUITE_COUNT);

        EXPECT_SUCCESS(s2n_connection_free(conn));
        free(private_key);
        free(cert_chain);
    }

    /* Test server cipher selection and scsv detection */
    {
        struct s2n_connection *conn;
        struct s2n_config *server_config;
        char *rsa_cert_chain_pem, *rsa_private_key_pem, *ecdsa_cert_chain_pem, *ecdsa_private_key_pem;
        struct s2n_cert_chain_and_key *rsa_cert, *ecdsa_cert;
        /* Allocate all of the objects and PEMs we'll need for this test. */
        EXPECT_NOT_NULL(rsa_cert_chain_pem = malloc(S2N_MAX_TEST_PEM_SIZE));
        EXPECT_NOT_NULL(rsa_private_key_pem = malloc(S2N_MAX_TEST_PEM_SIZE));
        EXPECT_NOT_NULL(ecdsa_cert_chain_pem = malloc(S2N_MAX_TEST_PEM_SIZE));
        EXPECT_NOT_NULL(ecdsa_private_key_pem = malloc(S2N_MAX_TEST_PEM_SIZE));
        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
        EXPECT_NOT_NULL(rsa_cert = s2n_cert_chain_and_key_new());
        EXPECT_NOT_NULL(ecdsa_cert = s2n_cert_chain_and_key_new());
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_CERT_CHAIN, rsa_cert_chain_pem, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_PRIVATE_KEY, rsa_private_key_pem, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_ECDSA_P384_PKCS1_CERT_CHAIN, ecdsa_cert_chain_pem, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_ECDSA_P384_PKCS1_KEY, ecdsa_private_key_pem, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(s2n_cert_chain_and_key_load_pem(rsa_cert, rsa_cert_chain_pem, rsa_private_key_pem));
        EXPECT_SUCCESS(s2n_cert_chain_and_key_load_pem(ecdsa_cert, ecdsa_cert_chain_pem, ecdsa_private_key_pem));

        uint8_t wire_ciphers[] = {
            TLS_RSA_WITH_RC4_128_MD5,
            TLS_RSA_WITH_RC4_128_SHA,
            TLS_RSA_WITH_3DES_EDE_CBC_SHA,
            TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA,
            TLS_RSA_WITH_AES_128_CBC_SHA,
            TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
            TLS_RSA_WITH_AES_256_CBC_SHA,
            TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
            TLS_RSA_WITH_AES_128_CBC_SHA256,
            TLS_RSA_WITH_AES_256_CBC_SHA256,
            TLS_DHE_RSA_WITH_AES_128_CBC_SHA256,
            TLS_DHE_RSA_WITH_AES_256_CBC_SHA256,
            TLS_RSA_WITH_AES_128_GCM_SHA256,
            TLS_RSA_WITH_AES_256_GCM_SHA384,
            TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
            TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
            TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
            TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
            TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
            TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
            TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
            TLS_ECDHE_BIKE_RSA_WITH_AES_256_GCM_SHA384,
            TLS_ECDHE_BIKE_RSA_WITH_AES_256_GCM_SHA384,
        };
        const uint8_t cipher_count = sizeof(wire_ciphers) / S2N_TLS_CIPHER_SUITE_LEN;

        uint8_t wire_ciphers_fallback[] = {
            TLS_RSA_WITH_RC4_128_MD5,
            TLS_RSA_WITH_RC4_128_SHA,
            TLS_RSA_WITH_3DES_EDE_CBC_SHA,
            TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA,
            TLS_RSA_WITH_AES_128_CBC_SHA,
            TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
            TLS_RSA_WITH_AES_256_CBC_SHA,
            TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
            TLS_RSA_WITH_AES_128_CBC_SHA256,
            TLS_RSA_WITH_AES_256_CBC_SHA256,
            TLS_DHE_RSA_WITH_AES_128_CBC_SHA256,
            TLS_DHE_RSA_WITH_AES_256_CBC_SHA256,
            TLS_RSA_WITH_AES_128_GCM_SHA256,
            TLS_RSA_WITH_AES_256_GCM_SHA384,
            TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
            TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
            TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
            TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
            TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
            TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
            TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
            TLS_FALLBACK_SCSV, /* At the end to verify it isn't missed */
        };
        const uint8_t cipher_count_fallback = sizeof(wire_ciphers_fallback) / S2N_TLS_CIPHER_SUITE_LEN;

        uint8_t wire_ciphers_renegotiation[] = {
            TLS_RSA_WITH_RC4_128_MD5,
            TLS_RSA_WITH_RC4_128_SHA,
            TLS_RSA_WITH_3DES_EDE_CBC_SHA,
            TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA,
            TLS_RSA_WITH_AES_128_CBC_SHA,
            TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
            TLS_RSA_WITH_AES_256_CBC_SHA,
            TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
            TLS_RSA_WITH_AES_128_CBC_SHA256,
            TLS_RSA_WITH_AES_256_CBC_SHA256,
            TLS_DHE_RSA_WITH_AES_128_CBC_SHA256,
            TLS_DHE_RSA_WITH_AES_256_CBC_SHA256,
            TLS_RSA_WITH_AES_128_GCM_SHA256,
            TLS_RSA_WITH_AES_256_GCM_SHA384,
            TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
            TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
            TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
            TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
            TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
            TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
            TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
            TLS_EMPTY_RENEGOTIATION_INFO_SCSV, /* At the end to verify it isn't missed */
        };
        const uint8_t cipher_count_renegotiation = sizeof(wire_ciphers_renegotiation) / S2N_TLS_CIPHER_SUITE_LEN;

        /* Only two ciphers for testing RSA vs ECDSA. */
        uint8_t wire_ciphers_with_ecdsa[] = {
            TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
            TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
        };
        const uint8_t cipher_count_ecdsa = sizeof(wire_ciphers_with_ecdsa) / S2N_TLS_CIPHER_SUITE_LEN;

        /* Only ECDSA ciphers */
        uint8_t wire_ciphers_only_ecdsa[] = {
            TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
            TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
            TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
            TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
        };
        const uint8_t cipher_count_only_ecdsa = sizeof(wire_ciphers_only_ecdsa) / S2N_TLS_CIPHER_SUITE_LEN;

        uint8_t wire_ciphers_rsa_fallback[] = {
            TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
            TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
            TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
            TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
            TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            TLS_RSA_WITH_AES_256_GCM_SHA384,
        };
        const uint8_t cipher_count_rsa_fallback = sizeof(wire_ciphers_rsa_fallback) / S2N_TLS_CIPHER_SUITE_LEN;

        EXPECT_NOT_NULL(server_config = s2n_config_new());
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(server_config, rsa_cert));
        EXPECT_SUCCESS(s2n_connection_set_config(conn, server_config));

        /* TEST RSA */
        EXPECT_SUCCESS(s2n_set_cipher_and_cert_as_tls_server(conn, wire_ciphers, cipher_count));
        EXPECT_EQUAL(conn->secure_renegotiation, 0);
        conn->actual_protocol_version = S2N_TLS10;
        EXPECT_EQUAL(1, s2n_connection_is_valid_for_cipher_preferences(conn, "test_all"));
        EXPECT_EQUAL(0, s2n_connection_is_valid_for_cipher_preferences(conn, "null"));
        EXPECT_SUCCESS(s2n_connection_wipe(conn));

        /* TEST RENEGOTIATION */
        EXPECT_SUCCESS(s2n_set_cipher_and_cert_as_tls_server(conn, wire_ciphers_renegotiation, cipher_count_renegotiation));
        EXPECT_EQUAL(conn->secure_renegotiation, 1);
        conn->actual_protocol_version = S2N_TLS12;
        EXPECT_EQUAL(1, s2n_connection_is_valid_for_cipher_preferences(conn, "test_all"));
        EXPECT_EQUAL(-1, s2n_connection_is_valid_for_cipher_preferences(conn, "not_exist"));
        EXPECT_SUCCESS(s2n_connection_wipe(conn));

        /* Simulate a TLSv11 client to trigger the fallback error */
        conn->client_protocol_version = S2N_TLS11;
        EXPECT_FAILURE(s2n_set_cipher_and_cert_as_tls_server(conn, wire_ciphers_fallback, cipher_count_fallback));
        EXPECT_EQUAL(conn->secure_renegotiation, 0);
        conn->actual_protocol_version = S2N_TLS11;
        EXPECT_EQUAL(1, s2n_connection_is_valid_for_cipher_preferences(conn, "null"));
        EXPECT_EQUAL(0, s2n_connection_is_valid_for_cipher_preferences(conn, "CloudFront-TLS-1-2-2018"));
        EXPECT_EQUAL(0, s2n_connection_is_valid_for_cipher_preferences(conn, "CloudFront-TLS-1-2-2019"));
        EXPECT_SUCCESS(s2n_connection_wipe(conn));

        /* TEST RSA cipher chosen when ECDSA cipher is at top */
        s2n_connection_set_cipher_preferences(conn, "test_ecdsa_priority");
        /* Assume default for negotiated curve. */
        /* Shouldn't be necessary unless the test fails, but we want the failure to be obvious. */
        conn->secure.server_ecc_evp_params.negotiated_curve = s2n_ecc_evp_supported_curves_list[0];
        const uint8_t expected_rsa_wire_choice[] = { TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA };
        EXPECT_SUCCESS(s2n_set_cipher_and_cert_as_tls_server(conn, wire_ciphers_with_ecdsa, cipher_count_ecdsa));
        EXPECT_EQUAL(conn->secure_renegotiation, 0);
        EXPECT_EQUAL(conn->secure.cipher_suite, s2n_cipher_suite_from_wire(expected_rsa_wire_choice));
        EXPECT_SUCCESS(s2n_connection_wipe(conn));

        /* Test that clients that support PQ ciphers can negotiate them. */
        const uint8_t expected_pq_wire_choice[] = { TLS_ECDHE_BIKE_RSA_WITH_AES_256_GCM_SHA384 };
        uint8_t client_extensions_data[] = {
                0xFE, 0x01, /* PQ KEM extension ID */
                0x00, 0x04, /* Total extension length in bytes */
                0x00, 0x02, /* Length of the supported parameters list in bytes */
                0x00, 0x01  /* BIKE1r1-Level1 */
        };
        int client_extensions_len = sizeof(client_extensions_data);
        s2n_connection_set_cipher_preferences(conn, "KMS-PQ-TLS-1-0-2019-06");
        conn->client_protocol_version = S2N_TLS12;
        conn->secure.server_ecc_evp_params.negotiated_curve = s2n_ecc_evp_supported_curves_list[0];
        conn->secure.client_pq_kem_extension.data = client_extensions_data;
        conn->secure.client_pq_kem_extension.size = client_extensions_len;
        EXPECT_SUCCESS(s2n_set_cipher_and_cert_as_tls_server(conn, wire_ciphers, cipher_count));
        EXPECT_EQUAL(conn->secure.cipher_suite, s2n_cipher_suite_from_wire(expected_pq_wire_choice));
        EXPECT_SUCCESS(s2n_connection_wipe(conn));

        /* Test cipher preferences that use PQ cipher suites that require TLS 1.2 fall back to classic ciphers if a client
         * only supports TLS 1.1 or below, TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA is the first cipher suite that supports
         * TLS 1.1 in KMS-PQ-TLS-1-0-2019-06 */
        for (int i = S2N_TLS10; i <= S2N_TLS11; i++) {
            const uint8_t expected_classic_wire_choice[] = { TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA };
            s2n_connection_set_cipher_preferences(conn, "KMS-PQ-TLS-1-0-2019-06");
            conn->client_protocol_version = i;
            conn->secure.server_ecc_evp_params.negotiated_curve = s2n_ecc_evp_supported_curves_list[0];
            conn->secure.client_pq_kem_extension.data = client_extensions_data;
            conn->secure.client_pq_kem_extension.size = client_extensions_len;
            EXPECT_SUCCESS(s2n_set_cipher_and_cert_as_tls_server(conn, wire_ciphers, cipher_count));
            EXPECT_EQUAL(conn->secure.cipher_suite, s2n_cipher_suite_from_wire(expected_classic_wire_choice));
            EXPECT_SUCCESS(s2n_connection_wipe(conn));
        }

        /* Clean+free to setup for ECDSA tests */
        EXPECT_SUCCESS(s2n_config_free(server_config));

        /* Set ECDSA CERT in s2n_config */
        EXPECT_NOT_NULL(server_config = s2n_config_new());
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(server_config, ecdsa_cert));
        EXPECT_SUCCESS(s2n_connection_set_config(conn, server_config));

        /* TEST ECDSA */
        s2n_connection_set_cipher_preferences(conn, "test_all_ecdsa");
        const uint8_t expected_ecdsa_wire_choice[] = { TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 };
        /* Assume default for negotiated curve. */
        conn->secure.server_ecc_evp_params.negotiated_curve = s2n_ecc_evp_supported_curves_list[0];
        EXPECT_SUCCESS(s2n_set_cipher_and_cert_as_tls_server(conn, wire_ciphers_with_ecdsa, cipher_count_ecdsa));
        EXPECT_EQUAL(conn->secure_renegotiation, 0);
        EXPECT_EQUAL(conn->secure.cipher_suite, s2n_cipher_suite_from_wire(expected_ecdsa_wire_choice));
        EXPECT_SUCCESS(s2n_connection_wipe(conn));

        /* TEST ECDSA cipher chosen when RSA cipher is at top */
        s2n_connection_set_cipher_preferences(conn, "test_all");
        /* Assume default for negotiated curve. */
        conn->secure.server_ecc_evp_params.negotiated_curve = s2n_ecc_evp_supported_curves_list[0];
        EXPECT_SUCCESS(s2n_set_cipher_and_cert_as_tls_server(conn, wire_ciphers_with_ecdsa, cipher_count_ecdsa));
        EXPECT_EQUAL(conn->secure_renegotiation, 0);
        EXPECT_EQUAL(conn->secure.cipher_suite, s2n_cipher_suite_from_wire(expected_ecdsa_wire_choice));
        EXPECT_SUCCESS(s2n_connection_wipe(conn));
        EXPECT_SUCCESS(s2n_config_free(server_config));

        /* TEST two certificates. Use two certs with different key types(RSA, ECDSA) and add them to a single
         * s2n_config.
         */
        EXPECT_NOT_NULL(server_config = s2n_config_new());
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(server_config, rsa_cert));
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(server_config, ecdsa_cert));

        /* Client sends RSA and ECDSA ciphers, server prioritizes ECDSA, ECDSA + RSA cert is configured */
        {
            const uint8_t expected_wire_choice[] = { TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 };
            s2n_connection_set_cipher_preferences(conn, "test_ecdsa_priority");
            conn->secure.server_ecc_evp_params.negotiated_curve = s2n_ecc_evp_supported_curves_list[0];
            EXPECT_SUCCESS(s2n_connection_set_config(conn, server_config));
            EXPECT_SUCCESS(s2n_set_cipher_and_cert_as_tls_server(conn, wire_ciphers_with_ecdsa, cipher_count_ecdsa));
            EXPECT_EQUAL(conn->secure_renegotiation, 0);
            EXPECT_EQUAL(conn->handshake_params.our_chain_and_key, ecdsa_cert);
            EXPECT_EQUAL(conn->secure.cipher_suite, s2n_cipher_suite_from_wire(expected_wire_choice));
            EXPECT_SUCCESS(s2n_connection_wipe(conn));
        }

        /* Client sends RSA and ECDSA ciphers, server prioritizes RSA, ECDSA + RSA cert is configured */
        {
            const uint8_t expected_wire_choice[] = { TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA };
            s2n_connection_set_cipher_preferences(conn, "test_all");
            conn->secure.server_ecc_evp_params.negotiated_curve = s2n_ecc_evp_supported_curves_list[0];
            EXPECT_SUCCESS(s2n_connection_set_config(conn, server_config));
            EXPECT_SUCCESS(s2n_set_cipher_and_cert_as_tls_server(conn, wire_ciphers_with_ecdsa, cipher_count_ecdsa));
            EXPECT_EQUAL(conn->secure_renegotiation, 0);
            EXPECT_EQUAL(conn->handshake_params.our_chain_and_key, rsa_cert);
            EXPECT_EQUAL(conn->secure.cipher_suite, s2n_cipher_suite_from_wire(expected_wire_choice));
            EXPECT_SUCCESS(s2n_connection_wipe(conn));
        }

        /* Client sends both RSA and ECDSA ciphers, server only configures RSA ciphers,
         * ECDSA + RSA cert is configured.
         */
        {
            const uint8_t expected_wire_choice[] = { TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA };
            /* 20170328 only supports RSA ciphers */
            s2n_connection_set_cipher_preferences(conn, "20170328");
            conn->secure.server_ecc_evp_params.negotiated_curve = s2n_ecc_evp_supported_curves_list[0];
            EXPECT_SUCCESS(s2n_connection_set_config(conn, server_config));
            EXPECT_SUCCESS(s2n_set_cipher_and_cert_as_tls_server(conn, wire_ciphers_with_ecdsa, cipher_count_ecdsa));
            EXPECT_EQUAL(conn->secure_renegotiation, 0);
            EXPECT_EQUAL(conn->handshake_params.our_chain_and_key, rsa_cert);
            EXPECT_EQUAL(conn->secure.cipher_suite, s2n_cipher_suite_from_wire(expected_wire_choice));
            EXPECT_SUCCESS(s2n_connection_wipe(conn));
        }

        /* Client sends both RSA and ECDSA ciphers, server only configures ECDSA ciphers, ECDSA + RSA cert is
         * configured.
         */
        {
            const uint8_t expected_wire_choice[] = { TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 };
            s2n_connection_set_cipher_preferences(conn, "test_all_ecdsa");
            conn->secure.server_ecc_evp_params.negotiated_curve = s2n_ecc_evp_supported_curves_list[0];
            EXPECT_SUCCESS(s2n_connection_set_config(conn, server_config));
            EXPECT_SUCCESS(s2n_set_cipher_and_cert_as_tls_server(conn, wire_ciphers_with_ecdsa, cipher_count_ecdsa));
            EXPECT_EQUAL(conn->secure_renegotiation, 0);
            EXPECT_EQUAL(conn->handshake_params.our_chain_and_key, ecdsa_cert);
            EXPECT_EQUAL(conn->secure.cipher_suite, s2n_cipher_suite_from_wire(expected_wire_choice));
            EXPECT_SUCCESS(s2n_connection_wipe(conn));
        }

        /* Client only sends RSA ciphers, server prioritizes ECDSA ciphers, ECDSA + RSA cert is
         * configured.
         */
        {
            const uint8_t expected_wire_choice[] = { TLS_RSA_WITH_RC4_128_MD5 };
            s2n_connection_set_cipher_preferences(conn, "test_ecdsa_priority");
            conn->secure.server_ecc_evp_params.negotiated_curve = s2n_ecc_evp_supported_curves_list[0];
            EXPECT_SUCCESS(s2n_connection_set_config(conn, server_config));
            EXPECT_SUCCESS(s2n_set_cipher_and_cert_as_tls_server(conn, wire_ciphers, cipher_count));
            EXPECT_EQUAL(conn->secure_renegotiation, 0);
            EXPECT_EQUAL(conn->handshake_params.our_chain_and_key, rsa_cert);
            EXPECT_EQUAL(conn->secure.cipher_suite, s2n_cipher_suite_from_wire(expected_wire_choice));
            EXPECT_SUCCESS(s2n_connection_wipe(conn));
        }

        /* Client only sends ECDSA ciphers, server prioritizes ECDSA ciphers, ECDSA + RSA cert is
         * configured.
         */
        {
            const uint8_t expected_wire_choice[] = { TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA };
            s2n_connection_set_cipher_preferences(conn, "test_ecdsa_priority");
            conn->secure.server_ecc_evp_params.negotiated_curve = s2n_ecc_evp_supported_curves_list[0];
            EXPECT_SUCCESS(s2n_connection_set_config(conn, server_config));
            EXPECT_SUCCESS(s2n_set_cipher_and_cert_as_tls_server(conn, wire_ciphers_only_ecdsa, cipher_count_only_ecdsa));
            EXPECT_EQUAL(conn->secure_renegotiation, 0);
            EXPECT_EQUAL(conn->handshake_params.our_chain_and_key, ecdsa_cert);
            EXPECT_EQUAL(conn->secure.cipher_suite, s2n_cipher_suite_from_wire(expected_wire_choice));
            EXPECT_SUCCESS(s2n_connection_wipe(conn));
        }

        /* Client sends ECDHE-ECDSA, RSA, ECDHE-RSA ciphers. Server prioritizes ECDSA but also supports RSA.
         * No mutually supported elliptic curves between client and server. ECDSA + RSA cert is configured.
         */
        {
            /* If there are no shared elliptic curves, we must fall through to a cipher that supports RSA kx.
             * This is the first RSA kx cipher that CloudFront-Upstream supports.
             */
            const uint8_t expected_wire_choice[] = { TLS_RSA_WITH_AES_256_GCM_SHA384 };
            /* Selecting this preference list because it prioritizes ECDHE-ECDSA and ECDHE-RSA over plain RSA kx. */
            s2n_connection_set_cipher_preferences(conn, "CloudFront-Upstream");
            /* No shared curve */
            conn->secure.server_ecc_evp_params.negotiated_curve = NULL;
            EXPECT_SUCCESS(s2n_connection_set_config(conn, server_config));
            EXPECT_SUCCESS(s2n_set_cipher_and_cert_as_tls_server(conn, wire_ciphers_rsa_fallback, cipher_count_rsa_fallback));
            EXPECT_EQUAL(conn->secure_renegotiation, 0);
            EXPECT_EQUAL(conn->handshake_params.our_chain_and_key, rsa_cert);
            EXPECT_EQUAL(conn->secure.cipher_suite, s2n_cipher_suite_from_wire(expected_wire_choice));
            EXPECT_SUCCESS(s2n_connection_wipe(conn));
        }
        EXPECT_SUCCESS(s2n_config_free(server_config));

        EXPECT_NOT_NULL(server_config = s2n_config_new());
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(server_config, rsa_cert));
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(server_config, ecdsa_cert));
        /* Override auto-chosen defaults with only RSA cert default. ECDSA still loaded, but not default. */
        EXPECT_SUCCESS(s2n_config_set_cert_chain_and_key_defaults(server_config, &rsa_cert, 1));

        /* Client sends RSA and ECDSA ciphers, server prioritizes ECDSA, ECDSA + RSA cert is configured,
         * only RSA is default. Expect default RSA used instead of previous test that expects ECDSA for this case. */
        {
            const uint8_t expected_wire_choice[] = { TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA };
            s2n_connection_set_cipher_preferences(conn, "test_ecdsa_priority");
            conn->secure.server_ecc_evp_params.negotiated_curve = s2n_ecc_evp_supported_curves_list[0];
            EXPECT_SUCCESS(s2n_connection_set_config(conn, server_config));
            EXPECT_SUCCESS(s2n_set_cipher_and_cert_as_tls_server(conn, wire_ciphers_with_ecdsa, cipher_count_ecdsa));
            EXPECT_EQUAL(conn->secure_renegotiation, 0);
            EXPECT_EQUAL(conn->handshake_params.our_chain_and_key, rsa_cert);
            EXPECT_EQUAL(conn->secure.cipher_suite, s2n_cipher_suite_from_wire(expected_wire_choice));
            EXPECT_SUCCESS(s2n_connection_wipe(conn));
        }

        /* Override auto-chosen defaults with only ECDSA cert default. RSA still loaded, but not default. */
        EXPECT_SUCCESS(s2n_config_set_cert_chain_and_key_defaults(server_config, &ecdsa_cert, 1));

        /* Client sends RSA and ECDSA ciphers, server prioritizes RSA, ECDSA + RSA cert is configured,
         * only ECDSA is default. Expect default ECDSA used instead of previous test that expects RSA for this case. */
        {
            const uint8_t expected_wire_choice[] = { TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 };
            s2n_connection_set_cipher_preferences(conn, "test_all");
            conn->secure.server_ecc_evp_params.negotiated_curve = s2n_ecc_evp_supported_curves_list[0];
            EXPECT_SUCCESS(s2n_connection_set_config(conn, server_config));
            EXPECT_SUCCESS(s2n_set_cipher_and_cert_as_tls_server(conn, wire_ciphers_with_ecdsa, cipher_count_ecdsa));
            EXPECT_EQUAL(conn->secure_renegotiation, 0);
            EXPECT_EQUAL(conn->handshake_params.our_chain_and_key, ecdsa_cert);
            EXPECT_EQUAL(conn->secure.cipher_suite, s2n_cipher_suite_from_wire(expected_wire_choice));
            EXPECT_SUCCESS(s2n_connection_wipe(conn));
        }

        /* Test override back to both RSA and ECDSA defaults. */
        struct s2n_cert_chain_and_key *certs_list[] = { rsa_cert, ecdsa_cert };
        EXPECT_SUCCESS(s2n_config_set_cert_chain_and_key_defaults(server_config, certs_list, 2));

        /* Client sends RSA and ECDSA ciphers, server prioritizes ECDSA, ECDSA + RSA cert is configured */
        {
            const uint8_t expected_wire_choice[] = { TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 };
            s2n_connection_set_cipher_preferences(conn, "test_ecdsa_priority");
            conn->secure.server_ecc_evp_params.negotiated_curve = s2n_ecc_evp_supported_curves_list[0];
            EXPECT_SUCCESS(s2n_connection_set_config(conn, server_config));
            EXPECT_SUCCESS(s2n_set_cipher_and_cert_as_tls_server(conn, wire_ciphers_with_ecdsa, cipher_count_ecdsa));
            EXPECT_EQUAL(conn->secure_renegotiation, 0);
            EXPECT_EQUAL(conn->handshake_params.our_chain_and_key, ecdsa_cert);
            EXPECT_EQUAL(conn->secure.cipher_suite, s2n_cipher_suite_from_wire(expected_wire_choice));
            EXPECT_SUCCESS(s2n_connection_wipe(conn));
        }

        /* Test that defaults are not overriden after failures to set new default certificates */
        EXPECT_FAILURE_WITH_ERRNO_NO_RESET(s2n_config_set_cert_chain_and_key_defaults(server_config, NULL, 0), S2N_ERR_NULL);
        EXPECT_EQUAL(strcmp(s2n_strerror_name(s2n_errno), "S2N_ERR_NULL"), 0);
        EXPECT_FAILURE_WITH_ERRNO_NO_RESET(s2n_config_set_cert_chain_and_key_defaults(server_config, &rsa_cert, 0),
                S2N_ERR_NUM_DEFAULT_CERTIFICATES);
        EXPECT_EQUAL(strcmp(s2n_strerror_name(s2n_errno), "S2N_ERR_NUM_DEFAULT_CERTIFICATES"), 0);
        struct s2n_cert_chain_and_key *rsa_certs_list[] = { rsa_cert, rsa_cert };
        EXPECT_FAILURE_WITH_ERRNO_NO_RESET(s2n_config_set_cert_chain_and_key_defaults(server_config, rsa_certs_list, 2),
                S2N_ERR_MULTIPLE_DEFAULT_CERTIFICATES_PER_AUTH_TYPE);
        EXPECT_EQUAL(strcmp(s2n_strerror_name(s2n_errno), "S2N_ERR_MULTIPLE_DEFAULT_CERTIFICATES_PER_AUTH_TYPE"), 0);
        /* Client sends RSA and ECDSA ciphers, server prioritizes RSA, ECDSA + RSA cert is configured.
         * RSA default certificate should be chosen. */
        {
            const uint8_t expected_wire_choice[] = { TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA };
            s2n_connection_set_cipher_preferences(conn, "test_all");
            conn->secure.server_ecc_evp_params.negotiated_curve = s2n_ecc_evp_supported_curves_list[0];
            EXPECT_SUCCESS(s2n_connection_set_config(conn, server_config));
            EXPECT_SUCCESS(s2n_set_cipher_and_cert_as_tls_server(conn, wire_ciphers_with_ecdsa, cipher_count_ecdsa));
            EXPECT_EQUAL(conn->secure_renegotiation, 0);
            EXPECT_EQUAL(conn->handshake_params.our_chain_and_key, rsa_cert);
            EXPECT_EQUAL(conn->secure.cipher_suite, s2n_cipher_suite_from_wire(expected_wire_choice));
            EXPECT_SUCCESS(s2n_connection_wipe(conn));
        }

        struct s2n_cipher_suite *tls12_cipher_suite = cipher_preferences_20170210.suites[cipher_preferences_20170210.count-1];
        uint8_t wire_ciphers_with_tls13[] = {
            TLS_AES_128_GCM_SHA256,
            TLS_AES_256_GCM_SHA384,
            TLS_CHACHA20_POLY1305_SHA256,
            tls12_cipher_suite->iana_value[0], tls12_cipher_suite->iana_value[1]
        };
        const uint8_t cipher_count_tls13 = sizeof(wire_ciphers_with_tls13) / S2N_TLS_CIPHER_SUITE_LEN;

        /* Client sends TLS1.3 cipher suites, but server does not support TLS1.3 */
        {
            s2n_connection_set_cipher_preferences(conn, "test_all");
            conn->client_protocol_version = S2N_TLS13;
            conn->actual_protocol_version = S2N_TLS12;
            EXPECT_SUCCESS(s2n_set_cipher_and_cert_as_tls_server(conn, wire_ciphers_with_tls13, cipher_count_tls13));
            EXPECT_EQUAL(conn->secure.cipher_suite, tls12_cipher_suite);
            EXPECT_SUCCESS(s2n_connection_wipe(conn));
        }

        /* Client sends TLS1.3 cipher suites, server selects TLS1.3 */
        {
            const uint8_t expected_wire_choice[] = { TLS_AES_256_GCM_SHA384 };
            s2n_connection_set_cipher_preferences(conn, "test_all");
            s2n_connection_set_cipher_preferences(conn, "default_tls13");
            conn->client_protocol_version = S2N_TLS13;
            conn->actual_protocol_version = S2N_TLS13;
            EXPECT_SUCCESS(s2n_set_cipher_and_cert_as_tls_server(conn, wire_ciphers_with_tls13, cipher_count_tls13));
            EXPECT_EQUAL(conn->secure.cipher_suite, s2n_cipher_suite_from_wire(expected_wire_choice));
            EXPECT_SUCCESS(s2n_connection_wipe(conn));
        }

        EXPECT_SUCCESS(s2n_config_free(server_config));
        EXPECT_SUCCESS(s2n_cert_chain_and_key_free(rsa_cert));
        EXPECT_SUCCESS(s2n_cert_chain_and_key_free(ecdsa_cert));
        free(ecdsa_cert_chain_pem);
        free(ecdsa_private_key_pem);
        free(rsa_cert_chain_pem);
        free(rsa_private_key_pem);
        EXPECT_SUCCESS(s2n_connection_free(conn));
    }
    END_TEST();
}
