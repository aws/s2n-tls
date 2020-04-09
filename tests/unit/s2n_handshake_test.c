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

#include <unistd.h>
#include <stdint.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>

#include <s2n.h>

#include "crypto/s2n_fips.h"
#include "crypto/s2n_rsa_pss.h"

#include "tls/s2n_connection.h"
#include "tls/s2n_handshake.h"
#include "tls/s2n_cipher_preferences.h"
#include "tls/s2n_cipher_suites.h"
#include "tls/s2n_tls13.h"
#include "utils/s2n_safety.h"

static int try_handshake(struct s2n_connection *server_conn, struct s2n_connection *client_conn)
{
    s2n_blocked_status server_blocked;
    s2n_blocked_status client_blocked;

    int tries = 0;
    do {
        int client_rc = s2n_negotiate(client_conn, &client_blocked);
        if (!(client_rc == 0 || (client_blocked && s2n_errno == S2N_ERR_BLOCKED))) {
            return -1;
        }

        int server_rc = s2n_negotiate(server_conn, &server_blocked);
        if (!(server_rc == 0 || (server_blocked && s2n_errno == S2N_ERR_BLOCKED) || server_blocked == S2N_BLOCKED_ON_APPLICATION_INPUT)) {
            return -1;
        }

        tries += 1;
        if (tries == 5) {
            return -1;
        }
    } while (client_blocked || server_blocked);

    uint8_t server_shutdown = 0;
    uint8_t client_shutdown = 0;
    do {
        if (!server_shutdown) {
            int server_rc = s2n_shutdown(server_conn, &server_blocked);
            if (server_rc == 0) {
                server_shutdown = 1;
            } else if (!(server_blocked && errno == EAGAIN)) {
                return -1;
            }
        }

        if (!client_shutdown) {
            int client_rc = s2n_shutdown(client_conn, &client_blocked);
            if (client_rc == 0) {
                client_shutdown = 1;
            } else if (!(client_blocked && errno == EAGAIN)) {
                return -1;
            }
        }
    } while (!server_shutdown || !client_shutdown);

    return 0;
}

int test_cipher_preferences(struct s2n_config *server_config, struct s2n_config *client_config,
        struct s2n_cert_chain_and_key *expected_cert_chain, s2n_signature_algorithm expected_sig_alg) {
    const struct s2n_cipher_preferences *cipher_preferences;

    cipher_preferences = server_config->cipher_preferences;
    notnull_check(cipher_preferences);

    if (s2n_is_in_fips_mode()) {
        /* Override default client config ciphers when in FIPS mode to ensure all FIPS
         * default ciphers are tested.
         */
        client_config->cipher_preferences = cipher_preferences;
        notnull_check(client_config->cipher_preferences);
    }

    /* Verify that a handshake succeeds for every available cipher in the default list. For unavailable ciphers,
     * make sure that we fail the handshake. */
    for (int cipher_idx = 0; cipher_idx < cipher_preferences->count; cipher_idx++) {
        struct s2n_cipher_preferences server_cipher_preferences;
        struct s2n_connection *client_conn;
        struct s2n_connection *server_conn;
        server_conn = s2n_connection_new(S2N_SERVER);
        notnull_check(server_conn);
        struct s2n_cipher_suite *expected_cipher = cipher_preferences->suites[cipher_idx];
        uint8_t expect_failure = 0;

        /* Expect failure if the libcrypto we're building with can't support the cipher */
        if (!expected_cipher->available) {
            expect_failure = 1;
        }

        /* Craft a cipher preference with a cipher_idx cipher
           NOTE: Its safe to use memcpy as the address of server_cipher_preferences
           will never be NULL */
        memcpy(&server_cipher_preferences, cipher_preferences, sizeof(server_cipher_preferences));
        server_cipher_preferences.count = 1;
        server_cipher_preferences.suites = &expected_cipher;
        server_conn->cipher_pref_override = &server_cipher_preferences;

        /* Create nonblocking pipes */
        struct s2n_test_piped_io piped_io;
        GUARD(s2n_piped_io_init_non_blocking(&piped_io));

        client_conn = s2n_connection_new(S2N_CLIENT);
        notnull_check(client_conn);
        GUARD(s2n_connection_set_piped_io(client_conn, &piped_io));
        GUARD(s2n_connection_set_config(client_conn, client_config));

        GUARD(s2n_connection_set_piped_io(server_conn, &piped_io));
        GUARD(s2n_connection_set_config(server_conn, server_config));

        if (!expect_failure) {
            GUARD(try_handshake(server_conn, client_conn));

            EXPECT_STRING_EQUAL(s2n_connection_get_cipher(server_conn), expected_cipher->name);

            EXPECT_EQUAL(server_conn->handshake_params.our_chain_and_key, expected_cert_chain);
            EXPECT_EQUAL(server_conn->secure.conn_sig_scheme.sig_alg, expected_sig_alg);

            EXPECT_TRUE(IS_NEGOTIATED(server_conn->handshake.handshake_type));
            EXPECT_TRUE(IS_NEGOTIATED(client_conn->handshake.handshake_type));

            EXPECT_TRUE(IS_FULL_HANDSHAKE(server_conn->handshake.handshake_type));
            EXPECT_TRUE(IS_FULL_HANDSHAKE(client_conn->handshake.handshake_type));

            EXPECT_STRING_EQUAL(s2n_connection_get_last_message_name(server_conn), "APPLICATION_DATA");
            EXPECT_STRING_EQUAL(s2n_connection_get_last_message_name(client_conn), "APPLICATION_DATA");
        } else {
            eq_check(try_handshake(server_conn, client_conn), -1);
            EXPECT_STRING_NOT_EQUAL(s2n_connection_get_last_message_name(server_conn), "APPLICATION_DATA");
            EXPECT_STRING_NOT_EQUAL(s2n_connection_get_last_message_name(client_conn), "APPLICATION_DATA");
        }

        GUARD(s2n_connection_free(server_conn));
        GUARD(s2n_connection_free(client_conn));
        GUARD(s2n_piped_io_close(&piped_io));
    }

    return 0;
}

int main(int argc, char **argv)
{
    BEGIN_TEST();

    char dhparams_pem[S2N_MAX_TEST_PEM_SIZE];
    EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_DHPARAMS, dhparams_pem, S2N_MAX_TEST_PEM_SIZE));

    /*  Test: RSA cert */
    {
        struct s2n_config *server_config, *client_config;

        struct s2n_cert_chain_and_key *chain_and_key;
        EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&chain_and_key,
                S2N_DEFAULT_TEST_CERT_CHAIN, S2N_DEFAULT_TEST_PRIVATE_KEY));

        EXPECT_NOT_NULL(server_config = s2n_config_new());
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(server_config, chain_and_key));
        EXPECT_SUCCESS(s2n_config_add_dhparams(server_config, dhparams_pem));

        GUARD_NONNULL(client_config = s2n_config_new());
        GUARD(s2n_config_set_unsafe_for_testing(client_config));

        EXPECT_SUCCESS(s2n_config_set_verification_ca_location(client_config, S2N_DEFAULT_TEST_CERT_CHAIN, NULL));

        EXPECT_SUCCESS(test_cipher_preferences(server_config, client_config,
                chain_and_key, S2N_SIGNATURE_RSA));

        EXPECT_SUCCESS(s2n_cert_chain_and_key_free(chain_and_key));
        EXPECT_SUCCESS(s2n_config_free(server_config));
        EXPECT_SUCCESS(s2n_config_free(client_config));
    }

    /*  Test: RSA (TLS 1.2) key exchanges with TLS 1.3 client */
    {
        if (!s2n_is_in_fips_mode()) {
            /* Enable TLS 1.3 for the client */
            EXPECT_SUCCESS(s2n_enable_tls13());
            struct s2n_config *server_config, *client_config;

            struct s2n_cert_chain_and_key *chain_and_key;
            EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&chain_and_key,
                    S2N_DEFAULT_TEST_CERT_CHAIN, S2N_DEFAULT_TEST_PRIVATE_KEY));

            EXPECT_NOT_NULL(server_config = s2n_config_new());
            /* Configures server with maximum version 1.2 with only RSA key exchange ciphersuites */
            EXPECT_SUCCESS(s2n_config_set_cipher_preferences(server_config, "test_all_rsa_kex"));
            EXPECT_SUCCESS(s2n_config_set_signature_preferences(server_config, "default"));
            EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(server_config, chain_and_key));

            EXPECT_NOT_NULL(client_config = s2n_config_new());
            EXPECT_SUCCESS(s2n_config_set_signature_preferences(client_config, "default"));
            EXPECT_SUCCESS(s2n_config_set_cipher_preferences(client_config, "test_all"));
            EXPECT_SUCCESS(s2n_config_set_unsafe_for_testing(client_config));

            EXPECT_SUCCESS(s2n_config_set_verification_ca_location(client_config, S2N_DEFAULT_TEST_CERT_CHAIN, NULL));

            /* RSA encrypted premaster secret key exchange requires client versions
            * to be set and read correctly, this test covers the behavior with a 1.3 client */
            EXPECT_SUCCESS(test_cipher_preferences(server_config, client_config,
                    chain_and_key, S2N_SIGNATURE_RSA));

            EXPECT_SUCCESS(s2n_cert_chain_and_key_free(chain_and_key));
            EXPECT_SUCCESS(s2n_config_free(server_config));
            EXPECT_SUCCESS(s2n_config_free(client_config));
            EXPECT_SUCCESS(s2n_disable_tls13());
        }
    }

    /*  Test: ECDSA cert */
    {
        struct s2n_config *server_config, *client_config;

        struct s2n_cert_chain_and_key *chain_and_key;
        EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&chain_and_key,
                S2N_ECDSA_P384_PKCS1_CERT_CHAIN, S2N_ECDSA_P384_PKCS1_KEY));

        EXPECT_NOT_NULL(server_config = s2n_config_new());
        EXPECT_SUCCESS(s2n_config_set_cipher_preferences(server_config, "test_all_ecdsa"));
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(server_config, chain_and_key));
        EXPECT_SUCCESS(s2n_config_add_dhparams(server_config, dhparams_pem));

        EXPECT_NOT_NULL(client_config = s2n_config_new());
        EXPECT_SUCCESS(s2n_config_set_cipher_preferences(client_config, "test_all_ecdsa"));
        EXPECT_SUCCESS(s2n_config_set_unsafe_for_testing(client_config));

        EXPECT_SUCCESS(s2n_config_set_verification_ca_location(client_config, S2N_ECDSA_P384_PKCS1_CERT_CHAIN, NULL));

        EXPECT_SUCCESS(test_cipher_preferences(server_config, client_config,
                chain_and_key, S2N_SIGNATURE_ECDSA));

        EXPECT_SUCCESS(s2n_cert_chain_and_key_free(chain_and_key));
        EXPECT_SUCCESS(s2n_config_free(server_config));
        EXPECT_SUCCESS(s2n_config_free(client_config));
    }

    /*  Test: RSA cert with RSA PSS signatures */
    if (s2n_is_rsa_pss_signing_supported())
    {
        const struct s2n_signature_scheme* const rsa_pss_rsae_sig_schemes[] = {
                /* RSA PSS */
                &s2n_rsa_pss_rsae_sha256,
                &s2n_rsa_pss_rsae_sha384,
                &s2n_rsa_pss_rsae_sha512,
        };

        struct s2n_signature_preferences sig_prefs = {
            .count = 3,
            .signature_schemes = rsa_pss_rsae_sig_schemes,
        };

        struct s2n_config *server_config, *client_config;

        struct s2n_cert_chain_and_key *chain_and_key;
        EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&chain_and_key,
                S2N_DEFAULT_TEST_CERT_CHAIN, S2N_DEFAULT_TEST_PRIVATE_KEY));

        EXPECT_NOT_NULL(server_config = s2n_config_new());
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(server_config, chain_and_key));
        EXPECT_SUCCESS(s2n_config_add_dhparams(server_config, dhparams_pem));
        server_config->signature_preferences = &sig_prefs;

        EXPECT_NOT_NULL(client_config = s2n_config_new());
        client_config->client_cert_auth_type = S2N_CERT_AUTH_NONE;
        client_config->check_ocsp = 0;
        client_config->disable_x509_validation = 1;
        client_config->signature_preferences = &sig_prefs;

        EXPECT_SUCCESS(s2n_config_set_verification_ca_location(client_config, S2N_DEFAULT_TEST_CERT_CHAIN, NULL));

        EXPECT_SUCCESS(test_cipher_preferences(server_config, client_config,
                chain_and_key, S2N_SIGNATURE_RSA_PSS_RSAE));

        EXPECT_SUCCESS(s2n_cert_chain_and_key_free(chain_and_key));
        EXPECT_SUCCESS(s2n_config_free(server_config));
        EXPECT_SUCCESS(s2n_config_free(client_config));
    }

    /*  Test: RSA_PSS cert with RSA_PSS signatures */
    if (s2n_is_rsa_pss_certs_supported())
    {
        s2n_enable_tls13();

        struct s2n_config *server_config, *client_config;

        struct s2n_cert_chain_and_key *chain_and_key;
        EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&chain_and_key,
                S2N_RSA_PSS_2048_SHA256_LEAF_CERT, S2N_RSA_PSS_2048_SHA256_LEAF_KEY));

        EXPECT_NOT_NULL(server_config = s2n_config_new());
        EXPECT_SUCCESS(s2n_config_set_cipher_preferences(server_config, "test_all_tls13"));
        EXPECT_SUCCESS(s2n_config_set_signature_preferences(server_config, "20200207"));
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(server_config, chain_and_key));

        EXPECT_NOT_NULL(client_config = s2n_config_new());
        EXPECT_SUCCESS(s2n_config_set_cipher_preferences(client_config, "test_all_tls13"));
        EXPECT_SUCCESS(s2n_config_set_signature_preferences(client_config, "20200207"));
        client_config->client_cert_auth_type = S2N_CERT_AUTH_NONE;
        client_config->check_ocsp = 0;
        client_config->disable_x509_validation = 1;

        EXPECT_SUCCESS(test_cipher_preferences(server_config, client_config,
                chain_and_key, S2N_SIGNATURE_RSA_PSS_PSS));

        EXPECT_SUCCESS(s2n_cert_chain_and_key_free(chain_and_key));
        EXPECT_SUCCESS(s2n_config_free(server_config));
        EXPECT_SUCCESS(s2n_config_free(client_config));

        s2n_disable_tls13();
    }

    END_TEST();
    return 0;
}

