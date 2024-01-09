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

#include "tls/s2n_handshake.h"

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>

#include "api/s2n.h"
#include "crypto/s2n_fips.h"
#include "crypto/s2n_rsa_pss.h"
#include "s2n_test.h"
#include "testlib/s2n_testlib.h"
#include "tls/s2n_cipher_suites.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_security_policies.h"
#include "tls/s2n_tls13.h"
#include "utils/s2n_safety.h"

enum test_type {
    TEST_TYPE_START,
    TEST_TYPE_SYNC = TEST_TYPE_START,
    TEST_TYPE_ASYNC,
    TEST_TYPE_END
} test_type;

struct s2n_async_pkey_op *pkey_op = NULL;
int async_pkey_op_called = 0;
int async_pkey_op_performed = 0;

static int handle_async(struct s2n_connection *server_conn)
{
    s2n_blocked_status server_blocked;

    /* Test that handshake can't proceed until async pkey op is complete */
    EXPECT_FAILURE_WITH_ERRNO(s2n_negotiate(server_conn, &server_blocked), S2N_ERR_ASYNC_BLOCKED);

    /* Check that we have pkey_op */
    EXPECT_NOT_NULL(pkey_op);

    /* Test that not performed pkey can't be applied */
    EXPECT_FAILURE_WITH_ERRNO(s2n_async_pkey_op_apply(pkey_op, server_conn),
            S2N_ERR_ASYNC_NOT_PERFORMED);

    /* Extract pkey */
    struct s2n_cert_chain_and_key *chain_and_key = s2n_connection_get_selected_cert(server_conn);
    EXPECT_NOT_NULL(chain_and_key);

    s2n_cert_private_key *pkey = s2n_cert_chain_and_key_get_private_key(chain_and_key);
    EXPECT_NOT_NULL(pkey);

    /* Test that we can perform pkey operation only once */
    EXPECT_SUCCESS(s2n_async_pkey_op_perform(pkey_op, pkey));
    EXPECT_FAILURE_WITH_ERRNO(s2n_async_pkey_op_perform(pkey_op, pkey), S2N_ERR_ASYNC_ALREADY_PERFORMED);

    /* Test that pkey op can't be applied to connection other than original one */
    struct s2n_connection *server_conn2 = s2n_connection_new(S2N_SERVER);
    EXPECT_NOT_NULL(server_conn2);
    EXPECT_FAILURE_WITH_ERRNO(s2n_async_pkey_op_apply(pkey_op, server_conn2),
            S2N_ERR_ASYNC_WRONG_CONNECTION);
    EXPECT_SUCCESS(s2n_connection_free(server_conn2));

    /* Test that pkey op can be applied to original connection */
    EXPECT_SUCCESS(s2n_async_pkey_op_apply(pkey_op, server_conn));

    /* Test that pkey op can't be applied to original connection more than once */
    EXPECT_FAILURE_WITH_ERRNO(s2n_async_pkey_op_apply(pkey_op, server_conn),
            S2N_ERR_ASYNC_ALREADY_APPLIED);

    /* Free the pkey op */
    EXPECT_SUCCESS(s2n_async_pkey_op_free(pkey_op));
    pkey_op = NULL;

    async_pkey_op_performed++;

    return 0;
}

static int try_handshake(struct s2n_connection *server_conn, struct s2n_connection *client_conn)
{
    s2n_blocked_status server_blocked;
    s2n_blocked_status client_blocked;

    int tries = 0;
    do {
        int client_rc = s2n_negotiate(client_conn, &client_blocked);
        if (!(client_rc == 0 || (client_blocked && s2n_error_get_type(s2n_errno) == S2N_ERR_T_BLOCKED))) {
            return -1;
        }

        int server_rc = s2n_negotiate(server_conn, &server_blocked);
        if (!(server_rc == 0 || (server_blocked && s2n_error_get_type(s2n_errno) == S2N_ERR_T_BLOCKED))) {
            return -1;
        }

        if (server_blocked == S2N_BLOCKED_ON_APPLICATION_INPUT) {
            /* Only can happen in async tests */
            EXPECT_EQUAL(test_type, TEST_TYPE_ASYNC);
            EXPECT_SUCCESS(handle_async(server_conn));
        }

        EXPECT_NOT_EQUAL(++tries, 5);
    } while (client_blocked || server_blocked);

    POSIX_GUARD(s2n_shutdown_test_server_and_client(server_conn, client_conn));
    return S2N_SUCCESS;
}

int test_cipher_preferences(struct s2n_config *server_config, struct s2n_config *client_config,
        struct s2n_cert_chain_and_key *expected_cert_chain, s2n_signature_algorithm expected_sig_alg)
{
    const struct s2n_security_policy *security_policy = server_config->security_policy;
    EXPECT_NOT_NULL(security_policy);

    if (s2n_is_in_fips_mode()) {
        /* Override default client config ciphers when in FIPS mode to ensure all FIPS
         * default ciphers are tested.
         */
        client_config->security_policy = security_policy;
    }

    const struct s2n_cipher_preferences *cipher_preferences = security_policy->cipher_preferences;
    EXPECT_NOT_NULL(cipher_preferences);

    /* Verify that a handshake succeeds for every available cipher in the default list. */
    for (int cipher_idx = 0; cipher_idx < cipher_preferences->count; cipher_idx++) {
        struct s2n_cipher_suite *expected_cipher = cipher_preferences->suites[cipher_idx];
        uint8_t expect_failure = 0;

        /* Expect failure if the libcrypto we're building with can't support the cipher */
        if (!expected_cipher->available) {
            expect_failure = 1;
        }

        TEST_DEBUG_PRINT("Testing %s in %s mode, expect_failure=%d\n", expected_cipher->name,
                test_type == TEST_TYPE_SYNC ? "synchronous" : "asynchronous", expect_failure);

        struct s2n_security_policy server_security_policy;
        struct s2n_cipher_preferences server_cipher_preferences;
        struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT);
        struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER);
        EXPECT_NOT_NULL(client_conn);
        EXPECT_NOT_NULL(server_conn);

        /* Craft a cipher preference with a cipher_idx cipher and assign it to server */
        EXPECT_MEMCPY_SUCCESS(&server_cipher_preferences, cipher_preferences, sizeof(server_cipher_preferences));
        server_cipher_preferences.count = 1;
        server_cipher_preferences.suites = &expected_cipher;

        EXPECT_MEMCPY_SUCCESS(&server_security_policy, security_policy, sizeof(server_security_policy));
        server_security_policy.cipher_preferences = &server_cipher_preferences;

        server_conn->security_policy_override = &server_security_policy;

        /* Create nonblocking pipes */
        struct s2n_test_io_pair io_pair;
        EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));

        EXPECT_SUCCESS(s2n_connection_set_io_pair(client_conn, &io_pair));
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, client_config));

        EXPECT_SUCCESS(s2n_connection_set_io_pair(server_conn, &io_pair));
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, server_config));

        /* Reset counters */
        async_pkey_op_called = 0;
        async_pkey_op_performed = 0;

        if (!expect_failure) {
            POSIX_GUARD(try_handshake(server_conn, client_conn));

            EXPECT_STRING_EQUAL(s2n_connection_get_cipher(server_conn), expected_cipher->name);

            EXPECT_EQUAL(server_conn->handshake_params.our_chain_and_key, expected_cert_chain);
            EXPECT_NOT_NULL(server_conn->handshake_params.server_cert_sig_scheme);
            EXPECT_EQUAL(server_conn->handshake_params.server_cert_sig_scheme->sig_alg, expected_sig_alg);

            EXPECT_TRUE(IS_NEGOTIATED(server_conn));
            EXPECT_TRUE(IS_NEGOTIATED(client_conn));

            EXPECT_TRUE(IS_FULL_HANDSHAKE(server_conn));
            EXPECT_TRUE(IS_FULL_HANDSHAKE(client_conn));

            EXPECT_STRING_EQUAL(s2n_connection_get_last_message_name(server_conn), "APPLICATION_DATA");
            EXPECT_STRING_EQUAL(s2n_connection_get_last_message_name(client_conn), "APPLICATION_DATA");

            if (test_type == TEST_TYPE_ASYNC) {
                EXPECT_EQUAL(async_pkey_op_called, 1);
                EXPECT_EQUAL(async_pkey_op_performed, 1);
            } else {
                EXPECT_EQUAL(async_pkey_op_called, 0);
                EXPECT_EQUAL(async_pkey_op_performed, 0);
            }
        } else {
            POSIX_ENSURE_EQ(try_handshake(server_conn, client_conn), -1);
            EXPECT_STRING_NOT_EQUAL(s2n_connection_get_last_message_name(server_conn), "APPLICATION_DATA");
            EXPECT_STRING_NOT_EQUAL(s2n_connection_get_last_message_name(client_conn), "APPLICATION_DATA");
            EXPECT_EQUAL(async_pkey_op_called, 0);
            EXPECT_EQUAL(async_pkey_op_performed, 0);
        }

        EXPECT_SUCCESS(s2n_connection_free(server_conn));
        EXPECT_SUCCESS(s2n_connection_free(client_conn));
        EXPECT_SUCCESS(s2n_io_pair_close(&io_pair));
    }

    return 0;
}

int async_pkey_fn(struct s2n_connection *conn, struct s2n_async_pkey_op *op)
{
    /* Just store the op, we will process it later */
    pkey_op = op;
    async_pkey_op_called++;

    return 0;
}

int main(int argc, char **argv)
{
    BEGIN_TEST();
    EXPECT_SUCCESS(s2n_disable_tls13_in_test());

    char dhparams_pem[S2N_MAX_TEST_PEM_SIZE];
    EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_DHPARAMS, dhparams_pem, S2N_MAX_TEST_PEM_SIZE));

    for (test_type = TEST_TYPE_START; test_type < TEST_TYPE_END; test_type++) {
        /*  Test: RSA cert */
        {
            struct s2n_config *server_config, *client_config;

            struct s2n_cert_chain_and_key *chain_and_key;
            EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&chain_and_key,
                    S2N_DEFAULT_TEST_CERT_CHAIN, S2N_DEFAULT_TEST_PRIVATE_KEY));

            EXPECT_NOT_NULL(server_config = s2n_config_new());
            /* We need a security policy that only supports RSA certificates for auth */
            EXPECT_SUCCESS(s2n_config_set_cipher_preferences(server_config, "20170210"));
            EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(server_config, chain_and_key));
            EXPECT_SUCCESS(s2n_config_add_dhparams(server_config, dhparams_pem));
            /* Enable signature validation */
            EXPECT_SUCCESS(s2n_config_set_verify_after_sign(server_config, S2N_VERIFY_AFTER_SIGN_ENABLED));
            if (test_type == TEST_TYPE_ASYNC) {
                EXPECT_SUCCESS(s2n_config_set_async_pkey_callback(server_config, async_pkey_fn));
            }

            EXPECT_NOT_NULL(client_config = s2n_config_new());
            EXPECT_SUCCESS(s2n_config_set_unsafe_for_testing(client_config));

            EXPECT_SUCCESS(s2n_config_set_verification_ca_location(client_config, S2N_DEFAULT_TEST_CERT_CHAIN, NULL));

            EXPECT_SUCCESS(test_cipher_preferences(server_config, client_config,
                    chain_and_key, S2N_SIGNATURE_RSA));

            EXPECT_SUCCESS(s2n_cert_chain_and_key_free(chain_and_key));
            EXPECT_SUCCESS(s2n_config_free(server_config));
            EXPECT_SUCCESS(s2n_config_free(client_config));
        };

        /*  Test: RSA (TLS 1.2) key exchanges with TLS 1.3 client */
        {
            if (!s2n_is_in_fips_mode()) {
                /* Enable TLS 1.3 for the client */
                EXPECT_SUCCESS(s2n_enable_tls13_in_test());
                struct s2n_config *server_config, *client_config;

                struct s2n_cert_chain_and_key *chain_and_key;
                EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&chain_and_key,
                        S2N_DEFAULT_TEST_CERT_CHAIN, S2N_DEFAULT_TEST_PRIVATE_KEY));

                EXPECT_NOT_NULL(server_config = s2n_config_new());
                /* Configures server with maximum version 1.2 with only RSA key exchange ciphersuites */
                EXPECT_SUCCESS(s2n_config_set_cipher_preferences(server_config, "test_all_rsa_kex"));
                EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(server_config, chain_and_key));
                /* Enable signature validation */
                EXPECT_SUCCESS(s2n_config_set_verify_after_sign(server_config, S2N_VERIFY_AFTER_SIGN_ENABLED));
                if (test_type == TEST_TYPE_ASYNC) {
                    EXPECT_SUCCESS(s2n_config_set_async_pkey_callback(server_config, async_pkey_fn));
                }

                EXPECT_NOT_NULL(client_config = s2n_config_new());
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
                EXPECT_SUCCESS(s2n_disable_tls13_in_test());
            }
        };

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
            /* Enable signature validation */
            EXPECT_SUCCESS(s2n_config_set_verify_after_sign(server_config, S2N_VERIFY_AFTER_SIGN_ENABLED));
            if (test_type == TEST_TYPE_ASYNC) {
                EXPECT_SUCCESS(s2n_config_set_async_pkey_callback(server_config, async_pkey_fn));
            }

            EXPECT_NOT_NULL(client_config = s2n_config_new());
            EXPECT_SUCCESS(s2n_config_set_cipher_preferences(client_config, "test_all_ecdsa"));
            EXPECT_SUCCESS(s2n_config_set_unsafe_for_testing(client_config));

            EXPECT_SUCCESS(s2n_config_set_verification_ca_location(client_config, S2N_ECDSA_P384_PKCS1_CERT_CHAIN, NULL));

            EXPECT_SUCCESS(test_cipher_preferences(server_config, client_config,
                    chain_and_key, S2N_SIGNATURE_ECDSA));

            EXPECT_SUCCESS(s2n_cert_chain_and_key_free(chain_and_key));
            EXPECT_SUCCESS(s2n_config_free(server_config));
            EXPECT_SUCCESS(s2n_config_free(client_config));
        };

        /*  Test: RSA cert with RSA PSS signatures */
        if (s2n_is_rsa_pss_signing_supported()) {
            const struct s2n_signature_scheme *const rsa_pss_rsae_sig_schemes[] = {
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
            /* We need a security policy that only supports RSA certificates for auth */
            EXPECT_SUCCESS(s2n_config_set_cipher_preferences(server_config, "20170210"));

            struct s2n_security_policy security_policy = {
                .minimum_protocol_version = server_config->security_policy->minimum_protocol_version,
                .cipher_preferences = server_config->security_policy->cipher_preferences,
                .kem_preferences = server_config->security_policy->kem_preferences,
                .signature_preferences = &sig_prefs,
                .ecc_preferences = server_config->security_policy->ecc_preferences,
            };

            EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(server_config, chain_and_key));
            EXPECT_SUCCESS(s2n_config_add_dhparams(server_config, dhparams_pem));
            if (test_type == TEST_TYPE_ASYNC) {
                EXPECT_SUCCESS(s2n_config_set_async_pkey_callback(server_config, async_pkey_fn));
            }
            server_config->security_policy = &security_policy;

            EXPECT_NOT_NULL(client_config = s2n_config_new());
            client_config->client_cert_auth_type = S2N_CERT_AUTH_NONE;
            client_config->check_ocsp = 0;
            client_config->disable_x509_validation = 1;
            client_config->security_policy = &security_policy;

            EXPECT_SUCCESS(s2n_config_set_verification_ca_location(client_config, S2N_DEFAULT_TEST_CERT_CHAIN, NULL));

            EXPECT_SUCCESS(test_cipher_preferences(server_config, client_config,
                    chain_and_key, S2N_SIGNATURE_RSA_PSS_RSAE));

            EXPECT_SUCCESS(s2n_cert_chain_and_key_free(chain_and_key));
            EXPECT_SUCCESS(s2n_config_free(server_config));
            EXPECT_SUCCESS(s2n_config_free(client_config));
        }

        /*  Test: RSA_PSS cert with RSA_PSS signatures */
        if (s2n_is_rsa_pss_certs_supported()) {
            s2n_enable_tls13_in_test();

            struct s2n_config *server_config, *client_config;

            struct s2n_cert_chain_and_key *chain_and_key;
            EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&chain_and_key,
                    S2N_RSA_PSS_2048_SHA256_LEAF_CERT, S2N_RSA_PSS_2048_SHA256_LEAF_KEY));

            EXPECT_NOT_NULL(server_config = s2n_config_new());
            EXPECT_SUCCESS(s2n_config_set_cipher_preferences(server_config, "20200207"));
            EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(server_config, chain_and_key));
            /* Enable signature validation */
            EXPECT_SUCCESS(s2n_config_set_verify_after_sign(server_config, S2N_VERIFY_AFTER_SIGN_ENABLED));
            if (test_type == TEST_TYPE_ASYNC) {
                EXPECT_SUCCESS(s2n_config_set_async_pkey_callback(server_config, async_pkey_fn));
            }

            EXPECT_NOT_NULL(client_config = s2n_config_new());
            EXPECT_SUCCESS(s2n_config_set_cipher_preferences(client_config, "20200207"));
            client_config->client_cert_auth_type = S2N_CERT_AUTH_NONE;
            client_config->check_ocsp = 0;
            client_config->disable_x509_validation = 1;

            EXPECT_SUCCESS(test_cipher_preferences(server_config, client_config,
                    chain_and_key, S2N_SIGNATURE_RSA_PSS_PSS));

            EXPECT_SUCCESS(s2n_cert_chain_and_key_free(chain_and_key));
            EXPECT_SUCCESS(s2n_config_free(server_config));
            EXPECT_SUCCESS(s2n_config_free(client_config));

            s2n_disable_tls13_in_test();
        }
    }

    END_TEST();
    return 0;
}
