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

#include <string.h>

#include "crypto/s2n_ecc_evp.h"
#include "pq-crypto/s2n_pq.h"
#include "tls/s2n_cipher_suites.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_security_policies.h"

static s2n_result s2n_conn_set_chosen_psk(struct s2n_connection *conn) {
    RESULT_ENSURE_REF(conn);

    uint8_t psk_identity[] = "psk identity";
    RESULT_GUARD(s2n_array_pushback(&conn->psk_params.psk_list, (void**) &conn->psk_params.chosen_psk));
    RESULT_ENSURE_REF(conn->psk_params.chosen_psk);
    RESULT_GUARD(s2n_psk_init(conn->psk_params.chosen_psk, S2N_PSK_TYPE_EXTERNAL));
    RESULT_GUARD_POSIX(s2n_psk_set_identity(conn->psk_params.chosen_psk, psk_identity, sizeof(psk_identity)));

    return S2N_RESULT_OK;
}

int main(int argc, char **argv)
{
    BEGIN_TEST();
    EXPECT_SUCCESS(s2n_disable_tls13());

    /* Test client cipher selection */
    {
        /* Setup connections */
        struct s2n_connection *conn = NULL;
        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));

        /* Setup config */
        struct s2n_cert_chain_and_key *chain_and_key = NULL;
        EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&chain_and_key,
                S2N_DEFAULT_TEST_CERT_CHAIN, S2N_DEFAULT_TEST_PRIVATE_KEY));
        struct s2n_config *config = NULL;
        EXPECT_NOT_NULL(config = s2n_config_new());
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, chain_and_key));
        EXPECT_SUCCESS(s2n_connection_set_config(conn, config));

        /* Test that the client allows the server to select ciphers that were offered in ClientHello */
        {
            conn->client_protocol_version = S2N_TLS13;
            conn->actual_protocol_version = S2N_TLS13;
            conn->server_protocol_version = S2N_TLS13;

            /* The client will offer the default tls13 ciphersuites */
            EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(conn, "default_tls13"));

            /* The server will send a TLS13 cipher over the wire */
            uint8_t valid_wire_ciphers[] = {
                TLS_AES_128_GCM_SHA256
            };

            /* We expect to succeed because the cipher was offered by the client */
            EXPECT_SUCCESS(s2n_set_cipher_as_client(conn, valid_wire_ciphers));

            EXPECT_SUCCESS(s2n_connection_wipe(conn));
        }

        /* Test that the client rejects a cipher that was not originally offered in ClientHello */
        {
            conn->client_protocol_version = S2N_TLS13;
            conn->actual_protocol_version = S2N_TLS13;
            conn->server_protocol_version = S2N_TLS13;

            /* The client will offer the default tls13 ciphersuites */
            EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(conn, "test_all_tls13"));

            /* The server will send a TLS12 cipher over the wire */
            uint8_t invalid_wire_ciphers[] = {
                TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
            };

            /* We expect to fail because the cipher was not offered by the client */
            EXPECT_FAILURE_WITH_ERRNO(s2n_set_cipher_as_client(conn, invalid_wire_ciphers), S2N_ERR_CIPHER_NOT_SUPPORTED);

            EXPECT_SUCCESS(s2n_connection_wipe(conn));
        }

        /** Clients MUST verify
         *= https://tools.ietf.org/rfc/rfc8446#section-4.2.11
         *= type=test
         *# that the server selected a cipher suite
         *# indicating a Hash associated with the PSK
         **/
        {
            /* If chosen PSK is set, test error case for incorrect hash match */
            {
                s2n_connection_set_cipher_preferences(conn, "default_tls13");

                EXPECT_OK(s2n_conn_set_chosen_psk(conn));

                uint8_t valid_tls13_wire_ciphers[] = {
                    TLS_AES_128_GCM_SHA256,
                };

                /* S2N_HMAC_SHA1 is not a matching hmac algorithm */
                conn->psk_params.chosen_psk->hmac_alg = S2N_HMAC_SHA1;
                EXPECT_FAILURE_WITH_ERRNO(s2n_set_cipher_as_client(conn, valid_tls13_wire_ciphers),
                                          S2N_ERR_CIPHER_NOT_SUPPORTED);
                EXPECT_EQUAL(conn->secure.cipher_suite, &s2n_null_cipher_suite);

                EXPECT_SUCCESS(s2n_connection_wipe(conn));
            }

            /* If chosen PSK is set, test success case for matching hash algorithm */
            {
                s2n_connection_set_cipher_preferences(conn, "default_tls13");

                EXPECT_OK(s2n_conn_set_chosen_psk(conn));

                uint8_t valid_tls13_wire_ciphers[] = {
                    TLS_AES_128_GCM_SHA256,
                };

                /* S2N_HASH_SHA256 is a matching hash algorithm for the cipher suite present in valid_tls13_wire_ciphers */
                conn->psk_params.chosen_psk->hmac_alg = S2N_HASH_SHA256;
                EXPECT_SUCCESS(s2n_set_cipher_as_client(conn, valid_tls13_wire_ciphers));
                EXPECT_EQUAL(conn->secure.cipher_suite, &s2n_tls13_aes_128_gcm_sha256);

                EXPECT_SUCCESS(s2n_connection_wipe(conn));
            }
        }

        EXPECT_SUCCESS(s2n_connection_free(conn));
        EXPECT_SUCCESS(s2n_cert_chain_and_key_free(chain_and_key));
        EXPECT_SUCCESS(s2n_config_free(config));
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
            TLS_ECDHE_SIKE_RSA_WITH_AES_256_GCM_SHA384,
            TLS_ECDHE_KYBER_RSA_WITH_AES_256_GCM_SHA384,
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
        conn->actual_protocol_version = S2N_TLS10;
        EXPECT_SUCCESS(s2n_set_cipher_as_tls_server(conn, wire_ciphers, cipher_count));
        EXPECT_EQUAL(conn->secure_renegotiation, 0);
        EXPECT_EQUAL(1, s2n_connection_is_valid_for_cipher_preferences(conn, "test_all"));
        EXPECT_EQUAL(0, s2n_connection_is_valid_for_cipher_preferences(conn, "null"));
        EXPECT_SUCCESS(s2n_connection_wipe(conn));

        /* TEST RENEGOTIATION */
        conn->actual_protocol_version = S2N_TLS12;
        EXPECT_SUCCESS(s2n_set_cipher_as_tls_server(conn, wire_ciphers_renegotiation, cipher_count_renegotiation));
        EXPECT_EQUAL(conn->secure_renegotiation, 1);
        EXPECT_EQUAL(1, s2n_connection_is_valid_for_cipher_preferences(conn, "test_all"));
        EXPECT_EQUAL(-1, s2n_connection_is_valid_for_cipher_preferences(conn, "not_exist"));
        EXPECT_SUCCESS(s2n_connection_wipe(conn));

        /* Simulate a TLSv11 client to trigger the fallback error */
        conn->actual_protocol_version = S2N_TLS11;
        EXPECT_FAILURE(s2n_set_cipher_as_tls_server(conn, wire_ciphers_fallback, cipher_count_fallback));
        EXPECT_EQUAL(conn->secure_renegotiation, 0);
        EXPECT_EQUAL(1, s2n_connection_is_valid_for_cipher_preferences(conn, "null"));
        EXPECT_EQUAL(0, s2n_connection_is_valid_for_cipher_preferences(conn, "CloudFront-TLS-1-2-2018"));
        EXPECT_EQUAL(0, s2n_connection_is_valid_for_cipher_preferences(conn, "CloudFront-TLS-1-2-2019"));
        EXPECT_SUCCESS(s2n_connection_wipe(conn));

        /* TEST RSA cipher chosen when ECDSA cipher is at top */
        EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(conn, "test_ecdsa_priority"));

        const struct s2n_ecc_preferences *ecc_pref = NULL;
        EXPECT_SUCCESS(s2n_connection_get_ecc_preferences(conn, &ecc_pref));
        EXPECT_NOT_NULL(ecc_pref);

        /* Assume default for negotiated curve. */
        /* Shouldn't be necessary unless the test fails, but we want the failure to be obvious. */
        conn->secure.server_ecc_evp_params.negotiated_curve = ecc_pref->ecc_curves[0];
        conn->actual_protocol_version = conn->server_protocol_version;
        const struct s2n_cipher_suite *expected_rsa_wire_choice = &s2n_ecdhe_rsa_with_aes_128_cbc_sha;
        EXPECT_SUCCESS(s2n_set_cipher_as_tls_server(conn, wire_ciphers_with_ecdsa, cipher_count_ecdsa));
        EXPECT_EQUAL(conn->secure_renegotiation, 0);
        EXPECT_EQUAL(conn->secure.cipher_suite, expected_rsa_wire_choice);
        EXPECT_SUCCESS(s2n_connection_wipe(conn));

        /* Test that PQ cipher suites are marked available/unavailable appropriately in s2n_cipher_suites_init() */
        {
            const struct s2n_cipher_suite *pq_suites[] = {
                    &s2n_ecdhe_sike_rsa_with_aes_256_gcm_sha384,
                    &s2n_ecdhe_bike_rsa_with_aes_256_gcm_sha384,
                    &s2n_ecdhe_kyber_rsa_with_aes_256_gcm_sha384,
            };

            for (size_t i = 0; i < s2n_array_len(pq_suites); i++) {
                if (s2n_pq_is_enabled()) {
                    EXPECT_EQUAL(pq_suites[i]->available, 1);
                    EXPECT_NOT_NULL(pq_suites[i]->record_alg);
                } else {
                    EXPECT_EQUAL(pq_suites[i]->available, 0);
                    EXPECT_NULL(pq_suites[i]->record_alg);
                }
            }
        }

        /* Test that clients that support PQ ciphers can negotiate them. */
        {
            uint8_t client_extensions_data[] = {
                    0xFE, 0x01, /* PQ KEM extension ID */
                    0x00, 0x04, /* Total extension length in bytes */
                    0x00, 0x02, /* Length of the supported parameters list in bytes */
                    0x00, 0x01  /* BIKE1r1-Level1 */
            };
            int client_extensions_len = sizeof(client_extensions_data);
            EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(conn, "KMS-PQ-TLS-1-0-2019-06"));
            conn->actual_protocol_version = S2N_TLS12;
            conn->secure.server_ecc_evp_params.negotiated_curve = ecc_pref->ecc_curves[0];
            conn->secure.client_pq_kem_extension.data = client_extensions_data;
            conn->secure.client_pq_kem_extension.size = client_extensions_len;
            EXPECT_SUCCESS(s2n_set_cipher_as_tls_server(conn, wire_ciphers, cipher_count));
            const struct s2n_cipher_suite *bike_cipher = &s2n_ecdhe_bike_rsa_with_aes_256_gcm_sha384;
            const struct s2n_cipher_suite *ecc_cipher = &s2n_ecdhe_rsa_with_aes_256_gcm_sha384;
            if (s2n_pq_is_enabled()) {
                EXPECT_EQUAL(conn->secure.cipher_suite, bike_cipher);
            } else {
                EXPECT_EQUAL(conn->secure.cipher_suite, ecc_cipher);
            }

            EXPECT_SUCCESS(s2n_connection_wipe(conn));

            /* Test cipher preferences that use PQ cipher suites that require TLS 1.2 fall back to classic ciphers if a client
             * only supports TLS 1.1 or below, TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA is the first cipher suite that supports
             * TLS 1.1 in KMS-PQ-TLS-1-0-2019-06 */
            for (int i = S2N_TLS10; i <= S2N_TLS11; i++) {
                const struct s2n_cipher_suite *expected_classic_wire_choice = &s2n_ecdhe_rsa_with_aes_256_cbc_sha;
                EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(conn, "KMS-PQ-TLS-1-0-2019-06"));
                conn->actual_protocol_version = i;
                conn->secure.server_ecc_evp_params.negotiated_curve = ecc_pref->ecc_curves[0];
                conn->secure.client_pq_kem_extension.data = client_extensions_data;
                conn->secure.client_pq_kem_extension.size = client_extensions_len;
                EXPECT_SUCCESS(s2n_set_cipher_as_tls_server(conn, wire_ciphers, cipher_count));
                EXPECT_EQUAL(conn->secure.cipher_suite, expected_classic_wire_choice);
                EXPECT_SUCCESS(s2n_connection_wipe(conn));
            }
        }

        /* Clean+free to setup for ECDSA tests */
        EXPECT_SUCCESS(s2n_config_free(server_config));

        /* Set ECDSA CERT in s2n_config */
        EXPECT_NOT_NULL(server_config = s2n_config_new());
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(server_config, ecdsa_cert));
        EXPECT_SUCCESS(s2n_connection_set_config(conn, server_config));

        EXPECT_SUCCESS(s2n_connection_get_ecc_preferences(conn, &ecc_pref));
        EXPECT_NOT_NULL(ecc_pref);

        /* TEST ECDSA */
        EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(conn, "test_all_ecdsa"));
        const struct s2n_cipher_suite *expected_ecdsa_wire_choice = &s2n_ecdhe_ecdsa_with_aes_128_cbc_sha256;
        /* Assume default for negotiated curve. */
        conn->secure.server_ecc_evp_params.negotiated_curve = ecc_pref->ecc_curves[0];
        conn->actual_protocol_version = conn->server_protocol_version;
        EXPECT_SUCCESS(s2n_set_cipher_as_tls_server(conn, wire_ciphers_with_ecdsa, cipher_count_ecdsa));
        EXPECT_EQUAL(conn->secure_renegotiation, 0);
        EXPECT_EQUAL(conn->secure.cipher_suite, expected_ecdsa_wire_choice);
        EXPECT_SUCCESS(s2n_connection_wipe(conn));

        /* TEST ECDSA cipher chosen when RSA cipher is at top */
        EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(conn, "test_all"));
        /* Assume default for negotiated curve. */
        conn->secure.server_ecc_evp_params.negotiated_curve = ecc_pref->ecc_curves[0];
        conn->actual_protocol_version = conn->server_protocol_version;
        EXPECT_SUCCESS(s2n_set_cipher_as_tls_server(conn, wire_ciphers_with_ecdsa, cipher_count_ecdsa));
        EXPECT_EQUAL(conn->secure_renegotiation, 0);
        EXPECT_EQUAL(conn->secure.cipher_suite, expected_ecdsa_wire_choice);
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
            const struct s2n_cipher_suite *expected_wire_choice = &s2n_ecdhe_ecdsa_with_aes_128_cbc_sha256;
            EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(conn, "test_ecdsa_priority"));
            conn->secure.server_ecc_evp_params.negotiated_curve = ecc_pref->ecc_curves[0];
            conn->actual_protocol_version = conn->server_protocol_version;
            EXPECT_SUCCESS(s2n_connection_set_config(conn, server_config));
            EXPECT_SUCCESS(s2n_set_cipher_as_tls_server(conn, wire_ciphers_with_ecdsa, cipher_count_ecdsa));
            EXPECT_EQUAL(conn->secure_renegotiation, 0);
            EXPECT_EQUAL(conn->secure.cipher_suite, expected_wire_choice);
            EXPECT_SUCCESS(s2n_connection_wipe(conn));
        }

        /* Client sends RSA and ECDSA ciphers, server prioritizes RSA, ECDSA + RSA cert is configured */
        {
            const struct s2n_cipher_suite *expected_wire_choice = &s2n_ecdhe_rsa_with_aes_128_cbc_sha;
            EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(conn, "test_all"));
            conn->secure.server_ecc_evp_params.negotiated_curve = ecc_pref->ecc_curves[0];
            conn->actual_protocol_version = conn->server_protocol_version;
            EXPECT_SUCCESS(s2n_connection_set_config(conn, server_config));
            EXPECT_SUCCESS(s2n_set_cipher_as_tls_server(conn, wire_ciphers_with_ecdsa, cipher_count_ecdsa));
            EXPECT_EQUAL(conn->secure_renegotiation, 0);
            EXPECT_EQUAL(conn->secure.cipher_suite, expected_wire_choice);
            EXPECT_SUCCESS(s2n_connection_wipe(conn));
        }

        /* Client sends both RSA and ECDSA ciphers, server only configures RSA ciphers,
         * ECDSA + RSA cert is configured.
         */
        {
            const struct s2n_cipher_suite *expected_wire_choice = &s2n_ecdhe_rsa_with_aes_128_cbc_sha;
            /* 20170328 only supports RSA ciphers */
            EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(conn, "20170328"));
            conn->secure.server_ecc_evp_params.negotiated_curve = ecc_pref->ecc_curves[0];
            conn->actual_protocol_version = conn->server_protocol_version;
            EXPECT_SUCCESS(s2n_connection_set_config(conn, server_config));
            EXPECT_SUCCESS(s2n_set_cipher_as_tls_server(conn, wire_ciphers_with_ecdsa, cipher_count_ecdsa));
            EXPECT_EQUAL(conn->secure_renegotiation, 0);
            EXPECT_EQUAL(conn->secure.cipher_suite, expected_wire_choice);
            EXPECT_SUCCESS(s2n_connection_wipe(conn));
        }

        /* Client sends both RSA and ECDSA ciphers, server only configures ECDSA ciphers, ECDSA + RSA cert is
         * configured.
         */
        {
            const struct s2n_cipher_suite *expected_wire_choice = &s2n_ecdhe_ecdsa_with_aes_128_cbc_sha256;
            EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(conn, "test_all_ecdsa"));
            conn->secure.server_ecc_evp_params.negotiated_curve = ecc_pref->ecc_curves[0];
            conn->actual_protocol_version = conn->server_protocol_version;
            EXPECT_SUCCESS(s2n_connection_set_config(conn, server_config));
            EXPECT_SUCCESS(s2n_set_cipher_as_tls_server(conn, wire_ciphers_with_ecdsa, cipher_count_ecdsa));
            EXPECT_EQUAL(conn->secure_renegotiation, 0);
            EXPECT_EQUAL(conn->secure.cipher_suite, expected_wire_choice);
            EXPECT_SUCCESS(s2n_connection_wipe(conn));
        }

        /* Client only sends RSA ciphers, server prioritizes ECDSA ciphers, ECDSA + RSA cert is
         * configured.
         */
        {
            const struct s2n_cipher_suite *expected_wire_choice = &s2n_rsa_with_rc4_128_md5;
            EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(conn, "test_ecdsa_priority"));
            conn->secure.server_ecc_evp_params.negotiated_curve = ecc_pref->ecc_curves[0];
            conn->actual_protocol_version = conn->server_protocol_version;
            EXPECT_SUCCESS(s2n_connection_set_config(conn, server_config));
            EXPECT_SUCCESS(s2n_set_cipher_as_tls_server(conn, wire_ciphers, cipher_count));
            EXPECT_EQUAL(conn->secure_renegotiation, 0);
            EXPECT_EQUAL(conn->secure.cipher_suite, expected_wire_choice);
            EXPECT_SUCCESS(s2n_connection_wipe(conn));
        }

        /* Client only sends ECDSA ciphers, server prioritizes ECDSA ciphers, ECDSA + RSA cert is
         * configured.
         */
        {
            const struct s2n_cipher_suite *expected_wire_choice = &s2n_ecdhe_ecdsa_with_aes_256_cbc_sha;
            EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(conn, "test_ecdsa_priority"));
            conn->secure.server_ecc_evp_params.negotiated_curve = ecc_pref->ecc_curves[0];
            conn->actual_protocol_version = conn->server_protocol_version;
            EXPECT_SUCCESS(s2n_connection_set_config(conn, server_config));
            EXPECT_SUCCESS(s2n_set_cipher_as_tls_server(conn, wire_ciphers_only_ecdsa, cipher_count_only_ecdsa));
            EXPECT_EQUAL(conn->secure_renegotiation, 0);
            EXPECT_EQUAL(conn->secure.cipher_suite, expected_wire_choice);
            EXPECT_SUCCESS(s2n_connection_wipe(conn));
        }

        /* Client sends ECDHE-ECDSA, RSA, ECDHE-RSA ciphers. Server prioritizes ECDSA but also supports RSA.
         * No mutually supported elliptic curves between client and server. ECDSA + RSA cert is configured.
         */
        {
            /* If there are no shared elliptic curves, we must fall through to a cipher that supports RSA kx.
             * This is the first RSA kx cipher that CloudFront-Upstream supports.
             */
            const struct s2n_cipher_suite *expected_wire_choice = &s2n_rsa_with_aes_256_gcm_sha384;
            /* Selecting this preference list because it prioritizes ECDHE-ECDSA and ECDHE-RSA over plain RSA kx. */
            EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(conn, "CloudFront-Upstream"));
            /* No shared curve */
            conn->secure.server_ecc_evp_params.negotiated_curve = NULL;
            conn->actual_protocol_version = conn->server_protocol_version;
            EXPECT_SUCCESS(s2n_connection_set_config(conn, server_config));
            EXPECT_SUCCESS(s2n_set_cipher_as_tls_server(conn, wire_ciphers_rsa_fallback, cipher_count_rsa_fallback));
            EXPECT_EQUAL(conn->secure_renegotiation, 0);
            EXPECT_EQUAL(conn->secure.cipher_suite, expected_wire_choice);
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
            const struct s2n_cipher_suite *expected_wire_choice = &s2n_ecdhe_rsa_with_aes_128_cbc_sha;
            EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(conn, "test_ecdsa_priority"));
            conn->secure.server_ecc_evp_params.negotiated_curve = ecc_pref->ecc_curves[0];
            conn->actual_protocol_version = conn->server_protocol_version;
            EXPECT_SUCCESS(s2n_connection_set_config(conn, server_config));
            EXPECT_SUCCESS(s2n_set_cipher_as_tls_server(conn, wire_ciphers_with_ecdsa, cipher_count_ecdsa));
            EXPECT_EQUAL(conn->secure_renegotiation, 0);
            EXPECT_EQUAL(conn->secure.cipher_suite, expected_wire_choice);
            EXPECT_SUCCESS(s2n_connection_wipe(conn));
        }

        /* Override auto-chosen defaults with only ECDSA cert default. RSA still loaded, but not default. */
        EXPECT_SUCCESS(s2n_config_set_cert_chain_and_key_defaults(server_config, &ecdsa_cert, 1));

        /* Client sends RSA and ECDSA ciphers, server prioritizes RSA, ECDSA + RSA cert is configured,
         * only ECDSA is default. Expect default ECDSA used instead of previous test that expects RSA for this case. */
        {
            const struct s2n_cipher_suite *expected_wire_choice = &s2n_ecdhe_ecdsa_with_aes_128_cbc_sha256;
            EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(conn, "test_all"));
            conn->secure.server_ecc_evp_params.negotiated_curve = ecc_pref->ecc_curves[0];
            conn->actual_protocol_version = conn->server_protocol_version;
            EXPECT_SUCCESS(s2n_connection_set_config(conn, server_config));
            EXPECT_SUCCESS(s2n_set_cipher_as_tls_server(conn, wire_ciphers_with_ecdsa, cipher_count_ecdsa));
            EXPECT_EQUAL(conn->secure_renegotiation, 0);
            EXPECT_EQUAL(conn->secure.cipher_suite, expected_wire_choice);
            EXPECT_SUCCESS(s2n_connection_wipe(conn));
        }

        /* Test override back to both RSA and ECDSA defaults. */
        struct s2n_cert_chain_and_key *certs_list[] = { rsa_cert, ecdsa_cert };
        EXPECT_SUCCESS(s2n_config_set_cert_chain_and_key_defaults(server_config, certs_list, 2));

        /* Client sends RSA and ECDSA ciphers, server prioritizes ECDSA, ECDSA + RSA cert is configured */
        {
            const struct s2n_cipher_suite *expected_wire_choice = &s2n_ecdhe_ecdsa_with_aes_128_cbc_sha256;
            EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(conn, "test_ecdsa_priority"));
            conn->secure.server_ecc_evp_params.negotiated_curve = ecc_pref->ecc_curves[0];
            conn->actual_protocol_version = conn->server_protocol_version;
            EXPECT_SUCCESS(s2n_connection_set_config(conn, server_config));
            EXPECT_SUCCESS(s2n_set_cipher_as_tls_server(conn, wire_ciphers_with_ecdsa, cipher_count_ecdsa));
            EXPECT_EQUAL(conn->secure_renegotiation, 0);
            EXPECT_EQUAL(conn->secure.cipher_suite, expected_wire_choice);
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
            const struct s2n_cipher_suite *expected_wire_choice = &s2n_ecdhe_rsa_with_aes_128_cbc_sha;
            EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(conn, "test_all"));
            conn->secure.server_ecc_evp_params.negotiated_curve = ecc_pref->ecc_curves[0];
            conn->actual_protocol_version = conn->server_protocol_version;
            EXPECT_SUCCESS(s2n_connection_set_config(conn, server_config));
            EXPECT_SUCCESS(s2n_set_cipher_as_tls_server(conn, wire_ciphers_with_ecdsa, cipher_count_ecdsa));
            EXPECT_EQUAL(conn->secure_renegotiation, 0);
            EXPECT_EQUAL(conn->secure.cipher_suite, expected_wire_choice);
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
            EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(conn, "test_all"));
            conn->client_protocol_version = S2N_TLS13;
            conn->actual_protocol_version = S2N_TLS12;
            EXPECT_SUCCESS(s2n_set_cipher_as_tls_server(conn, wire_ciphers_with_tls13, cipher_count_tls13));
            EXPECT_EQUAL(conn->secure.cipher_suite, tls12_cipher_suite);
            EXPECT_SUCCESS(s2n_connection_wipe(conn));
        }

        /* Client sends TLS1.3 cipher suites, server selects correct TLS1.3 ciphersuite */
        {
            struct test_case {
                const char *cipher_pref;
                const struct s2n_cipher_suite *expected_cipher_wire;
            };

            struct test_case test_cases[] = {
                { .cipher_pref = "default_tls13", .expected_cipher_wire = &s2n_tls13_aes_256_gcm_sha384 },
                { .cipher_pref = "test_all", .expected_cipher_wire = &s2n_tls13_aes_128_gcm_sha256 },
                { .cipher_pref = "test_all_tls13", .expected_cipher_wire = &s2n_tls13_aes_128_gcm_sha256 },
            };

            for (size_t i = 0; i < s2n_array_len(test_cases); i++) {
                EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(conn, test_cases[i].cipher_pref));
                conn->client_protocol_version = S2N_TLS13;
                conn->actual_protocol_version = S2N_TLS13;
                conn->server_protocol_version = S2N_TLS13;
                EXPECT_SUCCESS(s2n_set_cipher_as_tls_server(conn, wire_ciphers_with_tls13, cipher_count_tls13));
                EXPECT_EQUAL(conn->secure.cipher_suite, test_cases[i].expected_cipher_wire);
                EXPECT_SUCCESS(s2n_connection_wipe(conn));
            }
        }

        /* Check wire's cipher suites with preferred tls12 ordering does not affect tls13 selection */
        {
            uint8_t wire_ciphers2[] = {
                TLS_RSA_WITH_3DES_EDE_CBC_SHA,
                TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
                TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, /* tls 1.2 */
                TLS_CHACHA20_POLY1305_SHA256, /* tls 1.3 */
            };

            const uint8_t count = sizeof(wire_ciphers2) / S2N_TLS_CIPHER_SUITE_LEN;
            EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(conn, "test_all"));
            conn->client_protocol_version = S2N_TLS13;
            conn->actual_protocol_version = S2N_TLS13;
            conn->server_protocol_version = S2N_TLS13;

            if (s2n_chacha20_poly1305.is_available()) {
                EXPECT_SUCCESS(s2n_set_cipher_as_tls_server(conn, wire_ciphers2, count));
                EXPECT_EQUAL(conn->secure.cipher_suite, &s2n_tls13_chacha20_poly1305_sha256);
            } else {
                EXPECT_FAILURE(s2n_set_cipher_as_tls_server(conn, wire_ciphers2, count));
            }
            EXPECT_SUCCESS(s2n_connection_wipe(conn));
        }

        /* Test cipher suite with a required version higher than what connection supports should not be selected */
        {
            uint8_t test_wire_ciphers[] = {
                TLS_AES_128_GCM_SHA256, /* tls 1.3 */
                TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, /* tls 1.2 */
            };

            const uint8_t count = sizeof(test_wire_ciphers) / S2N_TLS_CIPHER_SUITE_LEN;
            EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(conn, "test_all"));
            conn->actual_protocol_version = S2N_TLS12;
            conn->secure.server_ecc_evp_params.negotiated_curve = s2n_all_supported_curves_list[0];

            EXPECT_SUCCESS(s2n_set_cipher_as_tls_server(conn, test_wire_ciphers, count));
            EXPECT_EQUAL(conn->secure.cipher_suite, &s2n_ecdhe_rsa_with_aes_128_gcm_sha256);
            EXPECT_SUCCESS(s2n_connection_wipe(conn));
        }

        /* We should skip cipher suites with a minimum protocol version unsupported by the connection.
         * If no valid cipher suite is found, we should fall back to a cipher suite with a higher protocol version,
         * but we should NEVER use a TLS1.3 suite on a pre-TLS1.3 connection or vice versa. */
        {
            /* Skip but fall back to cipher suite with protocol version higher than connection */
            {
                EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(conn, "test_all"));
                conn->secure.server_ecc_evp_params.negotiated_curve = s2n_all_supported_curves_list[0];

                uint8_t test_wire_ciphers[] = {
                    TLS_AES_128_GCM_SHA256, /* tls 1.3 */
                    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, /* tls 1.2 */
                    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, /* ssl v3 */
                };

                conn->actual_protocol_version = S2N_TLS10;

                /* If a match exists, skip the invalid cipher and choose it */
                EXPECT_SUCCESS(s2n_set_cipher_as_tls_server(conn, test_wire_ciphers, 3));
                EXPECT_EQUAL(conn->secure.cipher_suite, &s2n_ecdhe_rsa_with_aes_128_cbc_sha);

                /* If a match does not exist, choose the invalid cipher */
                EXPECT_SUCCESS(s2n_set_cipher_as_tls_server(conn, test_wire_ciphers, 2));
                EXPECT_EQUAL(conn->secure.cipher_suite, &s2n_ecdhe_rsa_with_aes_128_gcm_sha256);

                EXPECT_SUCCESS(s2n_connection_wipe(conn));
            }

            /* Skip and do NOT fall back to a TLS1.3 cipher suite if using TLS1.2 */
            {
                EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(conn, "test_all"));
                conn->secure.server_ecc_evp_params.negotiated_curve = s2n_all_supported_curves_list[0];

                uint8_t test_wire_ciphers[] = {
                        TLS_AES_128_GCM_SHA256, /* tls 1.3 */
                        TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, /* tls 1.2 */
                };

                conn->actual_protocol_version = S2N_TLS12;

                /* If a match exists, skip the invalid cipher and choose it */
                EXPECT_SUCCESS(s2n_set_cipher_as_tls_server(conn, test_wire_ciphers, 2));
                EXPECT_EQUAL(conn->secure.cipher_suite, &s2n_ecdhe_rsa_with_aes_128_gcm_sha256);

                /* If a match does not exist, fail to negotiate a cipher suite.
                 * We cannot fall back to the TLS1.3 choice. */
                EXPECT_FAILURE_WITH_ERRNO(s2n_set_cipher_as_tls_server(conn, test_wire_ciphers, 1),
                        S2N_ERR_CIPHER_NOT_SUPPORTED);

                EXPECT_SUCCESS(s2n_connection_wipe(conn));
            }

            /* Skip and do NOT fall back to a TLS1.2 cipher suite if using TLS1.3 */
            {
                EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(conn, "test_all"));
                conn->secure.server_ecc_evp_params.negotiated_curve = s2n_all_supported_curves_list[0];

                uint8_t test_wire_ciphers[] = {
                        TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, /* tls 1.2 */
                        TLS_AES_128_GCM_SHA256, /* tls 1.3 */
                };

                conn->actual_protocol_version = S2N_TLS13;

                /* If a match exists, skip the invalid cipher and choose it */
                EXPECT_SUCCESS(s2n_set_cipher_as_tls_server(conn, test_wire_ciphers, 2));
                EXPECT_EQUAL(conn->secure.cipher_suite, &s2n_tls13_aes_128_gcm_sha256);

                /* If a match does not exist, fail to negotiate a cipher suite.
                 * We cannot fall back to the TLS1.2 choice. */
                EXPECT_FAILURE_WITH_ERRNO(s2n_set_cipher_as_tls_server(conn, test_wire_ciphers, 1),
                        S2N_ERR_CIPHER_NOT_SUPPORTED);

                EXPECT_SUCCESS(s2n_connection_wipe(conn));
            }
        }

        /* If a PSK is being used, then the cipher suite must match the PSK's HMAC algorithm.
         *
         *= https://tools.ietf.org/rfc/rfc8446#section-4.2.11
         *= type=test
         *# The server MUST ensure that it selects a compatible PSK
         *# (if any) and cipher suite.
         **/
        {
            /* If chosen PSK is set, a cipher suite with matching HMAC algorithm must be selected */
            {
                s2n_connection_set_cipher_preferences(conn, "test_all");
                conn->secure.server_ecc_evp_params.negotiated_curve = s2n_all_supported_curves_list[0];
                conn->actual_protocol_version = S2N_TLS13;

                EXPECT_OK(s2n_conn_set_chosen_psk(conn));

                conn->psk_params.chosen_psk->hmac_alg = S2N_HMAC_SHA256;
                EXPECT_SUCCESS(s2n_set_cipher_as_tls_server(conn, wire_ciphers_with_tls13, cipher_count_tls13));
                EXPECT_EQUAL(conn->secure.cipher_suite->prf_alg, conn->psk_params.chosen_psk->hmac_alg);

                conn->psk_params.chosen_psk->hmac_alg = S2N_HMAC_SHA384;
                EXPECT_SUCCESS(s2n_set_cipher_as_tls_server(conn, wire_ciphers_with_tls13, cipher_count_tls13));
                EXPECT_EQUAL(conn->secure.cipher_suite->prf_alg, conn->psk_params.chosen_psk->hmac_alg);

                EXPECT_SUCCESS(s2n_connection_wipe(conn));
            }

            /* If chosen PSK is set but there is no matching cipher, the server MUST fail to set a cipher */
            {
                s2n_connection_set_cipher_preferences(conn, "test_all");
                conn->secure.server_ecc_evp_params.negotiated_curve = s2n_all_supported_curves_list[0];
                conn->actual_protocol_version = S2N_TLS13;

                /* S2N_HMAC_SHA1 is not a matching HMAC algorithm for any TLS1.3 cipher */
                EXPECT_OK(s2n_conn_set_chosen_psk(conn));
                conn->psk_params.chosen_psk->hmac_alg = S2N_HMAC_SHA1;

                EXPECT_FAILURE_WITH_ERRNO(s2n_set_cipher_as_tls_server(conn, wire_ciphers_with_tls13, cipher_count_tls13),
                        S2N_ERR_CIPHER_NOT_SUPPORTED);

                EXPECT_SUCCESS(s2n_connection_wipe(conn));
            }
        }

        /* Client sends cipher which is not in the configured suite */
        {
            EXPECT_SUCCESS(s2n_enable_tls13());
            uint8_t invalid_cipher_pref[] = {
                TLS_ECDHE_BIKE_RSA_WITH_AES_256_GCM_SHA384
            };

            const uint8_t invalid_cipher_count = sizeof(invalid_cipher_pref) / S2N_TLS_CIPHER_SUITE_LEN;
            EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(conn, "default_tls13"));
            conn->client_protocol_version = S2N_TLS13;
            conn->actual_protocol_version = S2N_TLS13;
            EXPECT_FAILURE_WITH_ERRNO(s2n_set_cipher_as_tls_server(conn, invalid_cipher_pref, invalid_cipher_count), S2N_ERR_CIPHER_NOT_SUPPORTED);
            EXPECT_SUCCESS(s2n_connection_wipe(conn));
            EXPECT_SUCCESS(s2n_disable_tls13());
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
