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

#include "tls/s2n_signature_algorithms.h"

#include "api/s2n.h"
#include "crypto/s2n_fips.h"
#include "crypto/s2n_rsa_pss.h"
#include "s2n_test.h"
#include "testlib/s2n_testlib.h"
#include "tls/s2n_cipher_suites.h"
#include "tls/s2n_config.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_security_policies.h"
#include "tls/s2n_signature_scheme.h"

#define LENGTH       (s2n_array_len(test_signature_schemes))
#define STUFFER_SIZE (LENGTH * TLS_SIGNATURE_SCHEME_LEN + 10)

#define RSA_CIPHER_SUITE   &s2n_ecdhe_rsa_with_aes_128_cbc_sha
#define ECDSA_CIPHER_SUITE &s2n_ecdhe_ecdsa_with_aes_128_cbc_sha
#define TLS13_CIPHER_SUITE &s2n_tls13_aes_128_gcm_sha256

const struct s2n_signature_scheme *const test_signature_schemes[] = {
    &s2n_ecdsa_secp384r1_sha384,
    &s2n_rsa_pkcs1_sha256,
    &s2n_rsa_pkcs1_sha224,
    &s2n_rsa_pkcs1_sha1,
    &s2n_ecdsa_sha1,
};

const struct s2n_signature_preferences test_preferences = {
    .count = LENGTH,
    .signature_schemes = test_signature_schemes,
};

int main(int argc, char **argv)
{
    BEGIN_TEST();
    EXPECT_SUCCESS(s2n_disable_tls13_in_test());

    struct s2n_cert_chain_and_key *rsa_cert_chain;
    EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&rsa_cert_chain,
            S2N_DEFAULT_TEST_CERT_CHAIN, S2N_DEFAULT_TEST_PRIVATE_KEY));

    struct s2n_cert_chain_and_key *ecdsa_cert_chain;
    EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&ecdsa_cert_chain,
            S2N_ECDSA_P384_PKCS1_CERT_CHAIN, S2N_ECDSA_P384_PKCS1_KEY));

    struct s2n_cert_chain_and_key *certs[] = { ecdsa_cert_chain, rsa_cert_chain };

    /* s2n_signature_algorithms_supported_list_send */
    {
        struct s2n_security_policy test_security_policy = *s2n_fetch_default_config()->security_policy;
        test_security_policy.signature_preferences = &test_preferences;

        /* Test: if all signatures supported, send all signatures */
        {
            DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT),
                    s2n_connection_ptr_free);
            EXPECT_NOT_NULL(conn);
            conn->security_policy_override = &test_security_policy;
            conn->actual_protocol_version = S2N_TLS13;

            DEFER_CLEANUP(struct s2n_stuffer result = { 0 }, s2n_stuffer_free);
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&result, 0));
            EXPECT_OK(s2n_signature_algorithms_supported_list_send(conn, &result));

            uint16_t size = 0;
            EXPECT_SUCCESS(s2n_stuffer_read_uint16(&result, &size));
            EXPECT_EQUAL(size, s2n_stuffer_data_available(&result));

            for (size_t i = 0; i < s2n_array_len(test_signature_schemes); i++) {
                uint16_t iana_value = 0;
                EXPECT_SUCCESS(s2n_stuffer_read_uint16(&result, &iana_value));
                EXPECT_EQUAL(iana_value, test_signature_schemes[i]->iana_value);
            }
            EXPECT_EQUAL(s2n_stuffer_data_available(&result), 0);
        };

        /* Test: do not send unsupported signatures */
        {
            DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT),
                    s2n_connection_ptr_free);
            EXPECT_NOT_NULL(conn);
            conn->security_policy_override = &test_security_policy;
            conn->actual_protocol_version = S2N_TLS12;

            DEFER_CLEANUP(struct s2n_stuffer result = { 0 }, s2n_stuffer_free);
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&result, 0));
            EXPECT_OK(s2n_signature_algorithms_supported_list_send(conn, &result));

            uint16_t size = 0;
            EXPECT_SUCCESS(s2n_stuffer_read_uint16(&result, &size));
            EXPECT_EQUAL(size, s2n_stuffer_data_available(&result));

            for (size_t i = 0; i < s2n_array_len(test_signature_schemes); i++) {
                if (test_signature_schemes[i] != &s2n_ecdsa_secp384r1_sha384) {
                    uint16_t iana_value = 0;
                    EXPECT_SUCCESS(s2n_stuffer_read_uint16(&result, &iana_value));
                    EXPECT_EQUAL(iana_value, test_signature_schemes[i]->iana_value);
                }
            }
            EXPECT_EQUAL(s2n_stuffer_data_available(&result), 0);
        };

        /* Test: written signatures readable */
        {
            DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT),
                    s2n_connection_ptr_free);
            EXPECT_NOT_NULL(conn);
            conn->security_policy_override = &test_security_policy;
            conn->actual_protocol_version = S2N_TLS13;

            DEFER_CLEANUP(struct s2n_stuffer result = { 0 }, s2n_stuffer_free);
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&result, 0));
            EXPECT_OK(s2n_signature_algorithms_supported_list_send(conn, &result));

            struct s2n_sig_scheme_list signatures = { 0 };
            EXPECT_SUCCESS(s2n_recv_supported_sig_scheme_list(&result, &signatures));
            EXPECT_EQUAL(s2n_stuffer_data_available(&result), 0);

            EXPECT_EQUAL(signatures.len, s2n_array_len(test_signature_schemes));
            for (size_t i = 0; i < s2n_array_len(test_signature_schemes); i++) {
                EXPECT_EQUAL(signatures.iana_list[i], test_signature_schemes[i]->iana_value);
            }
        };

        /* Test: do not send TLS1.2 signature schemes if QUIC enabled */
        {
            DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT),
                    s2n_connection_ptr_free);
            EXPECT_NOT_NULL(conn);
            conn->security_policy_override = &test_security_policy;
            conn->actual_protocol_version = S2N_TLS13;
            conn->quic_enabled = true;

            DEFER_CLEANUP(struct s2n_stuffer result = { 0 }, s2n_stuffer_free);
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&result, 0));
            EXPECT_OK(s2n_signature_algorithms_supported_list_send(conn, &result));

            uint16_t size = 0;
            EXPECT_SUCCESS(s2n_stuffer_read_uint16(&result, &size));
            EXPECT_EQUAL(size, s2n_stuffer_data_available(&result));

            uint16_t iana_value = 0;
            EXPECT_SUCCESS(s2n_stuffer_read_uint16(&result, &iana_value));
            EXPECT_EQUAL(iana_value, s2n_ecdsa_secp384r1_sha384.iana_value);
            EXPECT_EQUAL(s2n_stuffer_data_available(&result), 0);
        };
    };

    /* s2n_get_and_validate_negotiated_signature_scheme */
    {
        struct s2n_config *config = s2n_config_new();

        struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT);
        s2n_connection_set_config(conn, config);

        const struct s2n_security_policy *security_policy = NULL;
        EXPECT_SUCCESS(s2n_connection_get_security_policy(conn, &security_policy));
        EXPECT_NOT_NULL(security_policy);

        struct s2n_security_policy test_security_policy = {
            .minimum_protocol_version = security_policy->minimum_protocol_version,
            .cipher_preferences = security_policy->cipher_preferences,
            .kem_preferences = security_policy->kem_preferences,
            .signature_preferences = &test_preferences,
            .ecc_preferences = security_policy->ecc_preferences,
        };

        config->security_policy = &test_security_policy;

        struct s2n_stuffer choice = { 0 };
        s2n_stuffer_growable_alloc(&choice, STUFFER_SIZE);

        /* Test: successfully choose valid signature */
        {
            const struct s2n_signature_scheme *result = NULL;

            s2n_stuffer_wipe(&choice);
            s2n_stuffer_write_uint16(&choice, s2n_rsa_pkcs1_sha256.iana_value);

            EXPECT_SUCCESS(s2n_get_and_validate_negotiated_signature_scheme(conn, &choice, &result));
            EXPECT_EQUAL(result, &s2n_rsa_pkcs1_sha256);
        };

        /* Test: don't negotiate invalid signatures (protocol not high enough) */
        {
            const struct s2n_signature_scheme *result = NULL;

            s2n_stuffer_wipe(&choice);
            s2n_stuffer_write_uint16(&choice, s2n_ecdsa_secp384r1_sha384.iana_value);

            conn->actual_protocol_version = S2N_TLS13;
            EXPECT_SUCCESS(s2n_get_and_validate_negotiated_signature_scheme(conn, &choice, &result));
            EXPECT_EQUAL(result, &s2n_ecdsa_secp384r1_sha384);

            s2n_stuffer_reread(&choice);
            conn->actual_protocol_version = S2N_TLS12;
            EXPECT_FAILURE_WITH_ERRNO(s2n_get_and_validate_negotiated_signature_scheme(conn, &choice, &result),
                    S2N_ERR_INVALID_SIGNATURE_SCHEME);
        };

        /* Test: don't negotiate invalid signatures (protocol too high) */
        {
            const struct s2n_signature_scheme *result = NULL;

            s2n_stuffer_wipe(&choice);
            s2n_stuffer_write_uint16(&choice, s2n_rsa_pkcs1_sha224.iana_value);

            conn->actual_protocol_version = S2N_TLS12;
            EXPECT_SUCCESS(s2n_get_and_validate_negotiated_signature_scheme(conn, &choice, &result));
            EXPECT_EQUAL(result, &s2n_rsa_pkcs1_sha224);

            s2n_stuffer_reread(&choice);
            conn->actual_protocol_version = S2N_TLS13;
            EXPECT_FAILURE_WITH_ERRNO(s2n_get_and_validate_negotiated_signature_scheme(conn, &choice, &result),
                    S2N_ERR_INVALID_SIGNATURE_SCHEME);
        };

        s2n_connection_free(conn);
        s2n_config_free(config);
        s2n_stuffer_free(&choice);
    };

    /* Test: choose correct signature for duplicate iana values.
     * Some signature schemes have the same iana, but are different for
     * different protocol versions. */
    {
        const struct s2n_signature_scheme *const dup_test_signature_schemes[] = {
            &s2n_ecdsa_secp384r1_sha384,
            &s2n_ecdsa_sha384,
        };

        const struct s2n_signature_preferences dup_test_preferences = {
            .count = 2,
            .signature_schemes = dup_test_signature_schemes,
        };

        struct s2n_config *config = s2n_config_new();

        struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT);
        s2n_connection_set_config(conn, config);

        const struct s2n_security_policy *security_policy = NULL;
        EXPECT_SUCCESS(s2n_connection_get_security_policy(conn, &security_policy));
        EXPECT_NOT_NULL(security_policy);

        struct s2n_security_policy test_security_policy = {
            .minimum_protocol_version = security_policy->minimum_protocol_version,
            .cipher_preferences = security_policy->cipher_preferences,
            .kem_preferences = security_policy->kem_preferences,
            .signature_preferences = &dup_test_preferences,
            .ecc_preferences = security_policy->ecc_preferences,
        };

        config->security_policy = &test_security_policy;

        struct s2n_stuffer choice = { 0 };
        s2n_stuffer_growable_alloc(&choice, STUFFER_SIZE);

        const struct s2n_signature_scheme *result = NULL;

        conn->actual_protocol_version = S2N_TLS13;
        s2n_stuffer_write_uint16(&choice, s2n_ecdsa_sha384.iana_value);
        EXPECT_SUCCESS(s2n_get_and_validate_negotiated_signature_scheme(conn, &choice, &result));
        EXPECT_EQUAL(result, &s2n_ecdsa_secp384r1_sha384);

        conn->actual_protocol_version = S2N_TLS12;
        s2n_stuffer_write_uint16(&choice, s2n_ecdsa_sha384.iana_value);
        EXPECT_SUCCESS(s2n_get_and_validate_negotiated_signature_scheme(conn, &choice, &result));
        EXPECT_EQUAL(result, &s2n_ecdsa_sha384);

        s2n_connection_free(conn);
        s2n_config_free(config);
        s2n_stuffer_free(&choice);
    };

    /* s2n_choose_default_sig_scheme */
    {
        /* This method is used by both the client and server to choose default schemes
         * for both themselves and for their peers, so it needs to behave the same regardless
         * of the connection mode.
         */
        s2n_mode modes[] = { S2N_CLIENT, S2N_SERVER };
        for (size_t i = 0; i < s2n_array_len(modes); i++) {
            struct s2n_config *config = s2n_config_new();
            struct s2n_connection *conn = s2n_connection_new(modes[i]);
            EXPECT_SUCCESS(s2n_connection_set_config(conn, config));

            const struct s2n_security_policy *security_policy = NULL;
            EXPECT_SUCCESS(s2n_connection_get_security_policy(conn, &security_policy));
            EXPECT_NOT_NULL(security_policy);

            struct s2n_security_policy test_security_policy = {
                .minimum_protocol_version = security_policy->minimum_protocol_version,
                .cipher_preferences = security_policy->cipher_preferences,
                .kem_preferences = security_policy->kem_preferences,
                .signature_preferences = &test_preferences,
                .ecc_preferences = security_policy->ecc_preferences,
            };

            config->security_policy = &test_security_policy;

            /*
             * For pre-TLS1.2, always choose either RSA or ECDSA depending on the auth method.
             * Only use RSA-SHA1 if forced to by FIPS.
             */
            {
                conn->actual_protocol_version = S2N_TLS10;

                /* For the server signature, the auth method must match the cipher suite. */
                {
                    /* Choose RSA for an RSA cipher suite. */
                    {
                        const struct s2n_signature_scheme *result = NULL;
                        conn->secure->cipher_suite = RSA_CIPHER_SUITE;
                        EXPECT_SUCCESS(s2n_choose_default_sig_scheme(conn, &result, S2N_SERVER));
                        EXPECT_EQUAL(result, &s2n_rsa_pkcs1_md5_sha1);
                    };

                    /* Choose ECDSA for a ECDSA cipher suite. */
                    {
                        const struct s2n_signature_scheme *result = NULL;
                        conn->secure->cipher_suite = ECDSA_CIPHER_SUITE;
                        EXPECT_SUCCESS(s2n_choose_default_sig_scheme(conn, &result, S2N_SERVER));
                        EXPECT_EQUAL(result, &s2n_ecdsa_sha1);
                    };

                    /* Ignore the type of the client certificate. */
                    {
                        const struct s2n_signature_scheme *result = NULL;
                        conn->secure->cipher_suite = ECDSA_CIPHER_SUITE;
                        conn->handshake_params.client_cert_pkey_type = S2N_PKEY_TYPE_RSA;
                        EXPECT_SUCCESS(s2n_choose_default_sig_scheme(conn, &result, S2N_SERVER));
                        EXPECT_EQUAL(result, &s2n_ecdsa_sha1);
                    };

                    /* When in doubt, choose RSA. */
                    {
                        const struct s2n_signature_scheme *result = NULL;
                        conn->secure->cipher_suite = TLS13_CIPHER_SUITE;
                        EXPECT_SUCCESS(s2n_choose_default_sig_scheme(conn, &result, S2N_SERVER));
                        EXPECT_EQUAL(result, &s2n_rsa_pkcs1_md5_sha1);
                    };
                };

                /* For the client signature, the auth type must match the type of the client certificate */
                {
                    /* Choose RSA for an RSA certificate */
                    {
                        const struct s2n_signature_scheme *result = NULL;
                        conn->handshake_params.client_cert_pkey_type = S2N_PKEY_TYPE_RSA;
                        EXPECT_SUCCESS(s2n_choose_default_sig_scheme(conn, &result, S2N_CLIENT));
                        EXPECT_EQUAL(result, &s2n_rsa_pkcs1_md5_sha1);
                    };

                    /* Choose ECDSA for a ECDSA certificate */
                    {
                        const struct s2n_signature_scheme *result = NULL;
                        conn->handshake_params.client_cert_pkey_type = S2N_PKEY_TYPE_ECDSA;
                        EXPECT_SUCCESS(s2n_choose_default_sig_scheme(conn, &result, S2N_CLIENT));
                        EXPECT_EQUAL(result, &s2n_ecdsa_sha1);
                    };

                    /* Ignore the auth type of the cipher suite */
                    {
                        const struct s2n_signature_scheme *result = NULL;
                        conn->secure->cipher_suite = RSA_CIPHER_SUITE;
                        conn->handshake_params.client_cert_pkey_type = S2N_PKEY_TYPE_ECDSA;
                        EXPECT_SUCCESS(s2n_choose_default_sig_scheme(conn, &result, S2N_CLIENT));
                        EXPECT_EQUAL(result, &s2n_ecdsa_sha1);
                    };
                };
            };

            /*
             * For TLS1.2, always choose either RSA-SHA1 or ECDSA depending on the auth method.
             */
            {
                conn->actual_protocol_version = S2N_TLS12;

                /* For the server signature, the auth method must match the cipher suite. */
                {
                    /* Choose RSA for an RSA cipher suite. */
                    {
                        const struct s2n_signature_scheme *result = NULL;
                        conn->secure->cipher_suite = RSA_CIPHER_SUITE;
                        EXPECT_SUCCESS(s2n_choose_default_sig_scheme(conn, &result, S2N_SERVER));
                        EXPECT_EQUAL(result, &s2n_rsa_pkcs1_sha1);
                    };

                    /* Choose ECDSA for a ECDSA cipher suite. */
                    {
                        const struct s2n_signature_scheme *result = NULL;
                        conn->secure->cipher_suite = ECDSA_CIPHER_SUITE;
                        EXPECT_SUCCESS(s2n_choose_default_sig_scheme(conn, &result, S2N_SERVER));
                        EXPECT_EQUAL(result, &s2n_ecdsa_sha1);
                    };

                    /* Ignore the type of the client certificate. */
                    {
                        const struct s2n_signature_scheme *result = NULL;
                        conn->secure->cipher_suite = ECDSA_CIPHER_SUITE;
                        conn->handshake_params.client_cert_pkey_type = S2N_PKEY_TYPE_RSA;
                        EXPECT_SUCCESS(s2n_choose_default_sig_scheme(conn, &result, S2N_SERVER));
                        EXPECT_EQUAL(result, &s2n_ecdsa_sha1);
                    };

                    /* When in doubt, choose RSA. */
                    {
                        const struct s2n_signature_scheme *result = NULL;
                        conn->secure->cipher_suite = TLS13_CIPHER_SUITE;
                        EXPECT_SUCCESS(s2n_choose_default_sig_scheme(conn, &result, S2N_SERVER));
                        EXPECT_EQUAL(result, &s2n_rsa_pkcs1_sha1);
                    };
                };

                /* For the client signature, the auth type must match the type of the client certificate */
                {
                    /* Choose RSA for an RSA certificate */
                    {
                        const struct s2n_signature_scheme *result = NULL;
                        conn->handshake_params.client_cert_pkey_type = S2N_PKEY_TYPE_RSA;
                        EXPECT_SUCCESS(s2n_choose_default_sig_scheme(conn, &result, S2N_CLIENT));
                        EXPECT_EQUAL(result, &s2n_rsa_pkcs1_sha1);
                    };

                    /* Choose ECDSA for a ECDSA certificate */
                    {
                        const struct s2n_signature_scheme *result = NULL;
                        conn->handshake_params.client_cert_pkey_type = S2N_PKEY_TYPE_ECDSA;
                        EXPECT_SUCCESS(s2n_choose_default_sig_scheme(conn, &result, S2N_CLIENT));
                        EXPECT_EQUAL(result, &s2n_ecdsa_sha1);
                    };

                    /* Ignore the auth type of the cipher suite */
                    {
                        const struct s2n_signature_scheme *result = NULL;
                        conn->secure->cipher_suite = RSA_CIPHER_SUITE;
                        conn->handshake_params.client_cert_pkey_type = S2N_PKEY_TYPE_ECDSA;
                        EXPECT_SUCCESS(s2n_choose_default_sig_scheme(conn, &result, S2N_CLIENT));
                        EXPECT_EQUAL(result, &s2n_ecdsa_sha1);
                    };
                };

                /* Do not fall back to a default if not allowed by security policy */
                {
                    const struct s2n_signature_scheme *const no_defaults[] = {
                        &s2n_ecdsa_secp384r1_sha384,
                        &s2n_rsa_pkcs1_sha256,
                        &s2n_rsa_pkcs1_sha224,
                    };

                    const struct s2n_signature_preferences no_defaults_preferences = {
                        .count = s2n_array_len(no_defaults),
                        .signature_schemes = test_signature_schemes,
                    };

                    struct s2n_security_policy no_defaults_security_policy = {
                        .minimum_protocol_version = security_policy->minimum_protocol_version,
                        .cipher_preferences = security_policy->cipher_preferences,
                        .kem_preferences = security_policy->kem_preferences,
                        .signature_preferences = &no_defaults_preferences,
                        .ecc_preferences = security_policy->ecc_preferences,
                    };
                    conn->security_policy_override = &no_defaults_security_policy;

                    /* Client / RSA */
                    {
                        const struct s2n_signature_scheme *actual = NULL;
                        conn->secure->cipher_suite = RSA_CIPHER_SUITE;
                        EXPECT_SUCCESS(s2n_choose_default_sig_scheme(conn, &actual, S2N_SERVER));
                        EXPECT_EQUAL(actual, &s2n_null_sig_scheme);
                    };

                    /* Server / ECDSA */
                    {
                        const struct s2n_signature_scheme *actual = NULL;
                        conn->handshake_params.client_cert_pkey_type = S2N_PKEY_TYPE_ECDSA;
                        EXPECT_SUCCESS(s2n_choose_default_sig_scheme(conn, &actual, S2N_CLIENT));
                        EXPECT_EQUAL(actual, &s2n_null_sig_scheme);
                    };
                };
            };

            s2n_connection_free(conn);
            s2n_config_free(config);
        }
    };

    /* s2n_choose_sig_scheme_from_peer_preference_list */
    {
        struct s2n_config *config = s2n_config_new();
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, rsa_cert_chain));
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, ecdsa_cert_chain));

        struct s2n_connection *conn = s2n_connection_new(S2N_SERVER);
        EXPECT_SUCCESS(s2n_connection_set_config(conn, config));

        const struct s2n_security_policy *security_policy = NULL;
        EXPECT_SUCCESS(s2n_connection_get_security_policy(conn, &security_policy));
        EXPECT_NOT_NULL(security_policy);

        struct s2n_security_policy test_security_policy = {
            .minimum_protocol_version = security_policy->minimum_protocol_version,
            .cipher_preferences = security_policy->cipher_preferences,
            .kem_preferences = security_policy->kem_preferences,
            .signature_preferences = &test_preferences,
            .ecc_preferences = security_policy->ecc_preferences,
        };

        config->security_policy = &test_security_policy;

        /* Test: no peer list */
        {
            const struct s2n_signature_scheme *result = NULL;

            conn->secure->cipher_suite = ECDSA_CIPHER_SUITE;
            conn->actual_protocol_version = S2N_TLS10;
            const struct s2n_signature_scheme *default_scheme = &s2n_ecdsa_sha1;

            /* Choose default if NULL peer list */
            EXPECT_SUCCESS(s2n_choose_sig_scheme_from_peer_preference_list(conn, NULL, &result));
            EXPECT_EQUAL(result, default_scheme);

            /* Choose default if empty peer list */
            struct s2n_sig_scheme_list peer_list = {
                .len = 0,
                .iana_list = { 0 },
            };
            EXPECT_SUCCESS(s2n_choose_sig_scheme_from_peer_preference_list(conn, &peer_list, &result));
            EXPECT_EQUAL(result, default_scheme);

            /* If we cannot find a match in TLS1.3, allow defaults for success */
            conn->secure->cipher_suite = TLS13_CIPHER_SUITE;
            conn->actual_protocol_version = S2N_TLS13;
            EXPECT_SUCCESS(s2n_choose_sig_scheme_from_peer_preference_list(conn, &peer_list, &result));
        };

        /* Test: no shared valid signature schemes, using TLS1.3. Server picks preferred */
        {
            const struct s2n_signature_scheme *result = NULL;

            conn->secure->cipher_suite = TLS13_CIPHER_SUITE;
            conn->actual_protocol_version = S2N_TLS13;

            struct s2n_sig_scheme_list peer_list = {
                .len = 2,
                .iana_list = {
                        s2n_rsa_pkcs1_sha224.iana_value, /* Invalid (wrong protocol version) */
                        s2n_rsa_pkcs1_sha1.iana_value,   /* Not in preference list */
                },
            };

            /* behavior is that we fallback to a preferred signature algorithm */
            EXPECT_SUCCESS(s2n_choose_sig_scheme_from_peer_preference_list(conn, &peer_list, &result));
            EXPECT_EQUAL(result, &s2n_ecdsa_secp384r1_sha384);
        };

        /* Test: no shared valid signature schemes, using TLS1.2 */
        {
            const struct s2n_signature_scheme *result = NULL;

            conn->secure->cipher_suite = TLS13_CIPHER_SUITE;
            conn->actual_protocol_version = S2N_TLS12;

            /* Peer list contains no signature schemes that we support */
            struct s2n_sig_scheme_list peer_list = {
                .len = 1,
                .iana_list = { 1 },
            };

            EXPECT_SUCCESS(s2n_choose_sig_scheme_from_peer_preference_list(conn, &peer_list, &result));

            /* Verify that we did not choose the peer's offered signature scheme */
            EXPECT_NOT_NULL(result);
            EXPECT_NOT_EQUAL(result->iana_value, peer_list.iana_list[0]);

            /* Verify that we chose the default signature scheme, even though it wasn't in
             * the peer's offered list. This proves that when we share no signature schemes
             * with the peer, then calling s2n_choose_sig_scheme_from_peer_preference_list
             * is equivalent to calling s2n_choose_default_sig_scheme. */
            const struct s2n_signature_scheme *default_scheme = NULL;
            EXPECT_SUCCESS(s2n_choose_default_sig_scheme(conn, &default_scheme, S2N_SERVER));
            EXPECT_EQUAL(result, default_scheme);
        };

        /* Test: choose valid signature from peer list */
        {
            const struct s2n_signature_scheme *result = NULL;

            conn->secure->cipher_suite = RSA_CIPHER_SUITE;
            conn->actual_protocol_version = S2N_TLS12;

            struct s2n_sig_scheme_list peer_list = {
                .len = 4,
                .iana_list = {
                        s2n_ecdsa_secp384r1_sha384.iana_value, /* Invalid: wrong protocol, wrong auth method */
                        s2n_rsa_pkcs1_sha1.iana_value,         /* Invalid: not in preference list */
                        s2n_rsa_pkcs1_sha256.iana_value,       /* Valid -- should be chosen */
                        s2n_rsa_pkcs1_sha224.iana_value,       /* Valid, but lower priority -- should not be chosen */
                },
            };

            EXPECT_SUCCESS(s2n_choose_sig_scheme_from_peer_preference_list(conn, &peer_list, &result));
            EXPECT_EQUAL(result, &s2n_rsa_pkcs1_sha256);
        };

        /* Test: invalid scheme, because wrong protocol version */
        {
            const struct s2n_signature_scheme *result = NULL;

            conn->secure->cipher_suite = RSA_CIPHER_SUITE;

            struct s2n_sig_scheme_list peer_list = {
                .len = 1,
                .iana_list = { s2n_rsa_pkcs1_sha224.iana_value },
            };

            conn->actual_protocol_version = S2N_TLS12;
            EXPECT_SUCCESS(s2n_choose_sig_scheme_from_peer_preference_list(conn, &peer_list, &result));
            EXPECT_EQUAL(result, &s2n_rsa_pkcs1_sha224);

            conn->actual_protocol_version = S2N_TLS13;
            EXPECT_FAILURE_WITH_ERRNO(s2n_choose_sig_scheme_from_peer_preference_list(conn, &peer_list, &result),
                    S2N_ERR_INVALID_SIGNATURE_SCHEME);
        };

        s2n_connection_free(conn);
        s2n_config_free(config);
    };

    /* Test: send and receive default signature preferences */
    for (size_t i = S2N_TLS10; i < S2N_TLS13; i++) {
        DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(conn);
        conn->actual_protocol_version = i;

        DEFER_CLEANUP(struct s2n_stuffer result = { 0 }, s2n_stuffer_free);
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&result, 0));
        EXPECT_OK(s2n_signature_algorithms_supported_list_send(conn, &result));

        struct s2n_sig_scheme_list signatures = { 0 };
        EXPECT_SUCCESS(s2n_recv_supported_sig_scheme_list(&result, &signatures));
        EXPECT_EQUAL(s2n_stuffer_data_available(&result), 0);

        /* Verify no duplicates - some preferences contain duplicates, but only
         * one should be valid at a time. */
        uint16_t iana = 0, other_iana = 0;
        for (size_t a = 0; a < signatures.len; a++) {
            iana = signatures.iana_list[a];
            for (int b = 0; b < signatures.len; b++) {
                if (a == b) {
                    continue;
                }
                other_iana = signatures.iana_list[b];
                EXPECT_NOT_EQUAL(iana, other_iana);
            }
        }
    };

    /* Test: libcrypto may not support PSS signatures */
    {
        const struct s2n_signature_scheme *const pss_test_signature_schemes[] = {
            &s2n_rsa_pss_rsae_sha256,
            &s2n_rsa_pss_pss_sha256,
        };

        const struct s2n_signature_preferences pss_test_preferences = {
            .count = 2,
            .signature_schemes = pss_test_signature_schemes,
        };

        struct s2n_config *config = s2n_config_new();
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, rsa_cert_chain));

        struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT);
        conn->secure->cipher_suite = TLS13_CIPHER_SUITE;
        conn->actual_protocol_version = S2N_TLS13;
        EXPECT_SUCCESS(s2n_connection_set_config(conn, config));

        const struct s2n_security_policy *security_policy = NULL;
        EXPECT_SUCCESS(s2n_connection_get_security_policy(conn, &security_policy));
        EXPECT_NOT_NULL(security_policy);

        struct s2n_security_policy test_security_policy = {
            .minimum_protocol_version = security_policy->minimum_protocol_version,
            .cipher_preferences = security_policy->cipher_preferences,
            .kem_preferences = security_policy->kem_preferences,
            .signature_preferences = &pss_test_preferences,
            .ecc_preferences = security_policy->ecc_preferences,
        };

        config->security_policy = &test_security_policy;

        /* Do not offer PSS signatures schemes if unsupported:
         * s2n_signature_algorithms_supported_list_send + PSS */
        {
            DEFER_CLEANUP(struct s2n_stuffer result = { 0 }, s2n_stuffer_free);
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&result, 0));
            EXPECT_OK(s2n_signature_algorithms_supported_list_send(conn, &result));

            uint16_t size = 0;
            EXPECT_SUCCESS(s2n_stuffer_read_uint16(&result, &size));
            EXPECT_EQUAL(size, s2n_stuffer_data_available(&result));
            if (s2n_is_rsa_pss_certs_supported()) {
                EXPECT_EQUAL(size, 2 * sizeof(uint16_t));
            } else if (s2n_is_rsa_pss_signing_supported()) {
                EXPECT_EQUAL(size, 1 * sizeof(uint16_t));
            } else {
                EXPECT_EQUAL(size, 0);
            }
        };

        /* Do not accept a PSS signature scheme if unsupported:
         * s2n_get_and_validate_negotiated_signature_scheme + PSS */
        {
            struct s2n_stuffer choice = { 0 };
            s2n_stuffer_growable_alloc(&choice, STUFFER_SIZE);
            s2n_stuffer_write_uint16(&choice, s2n_rsa_pss_rsae_sha256.iana_value);

            const struct s2n_signature_scheme *result = NULL;

            if (s2n_is_rsa_pss_signing_supported()) {
                EXPECT_SUCCESS(s2n_get_and_validate_negotiated_signature_scheme(conn, &choice, &result));
                EXPECT_EQUAL(result, &s2n_rsa_pss_rsae_sha256);
            } else {
                EXPECT_FAILURE_WITH_ERRNO(s2n_get_and_validate_negotiated_signature_scheme(conn, &choice, &result),
                        S2N_ERR_INVALID_SIGNATURE_SCHEME);
            }

            s2n_stuffer_free(&choice);
        };

        /* Do not choose a PSS signature scheme if unsupported:
         * s2n_choose_sig_scheme_from_peer_preference_list + PSS */
        {
            struct s2n_sig_scheme_list peer_list = {
                .len = 1,
                .iana_list = { s2n_rsa_pss_rsae_sha256.iana_value },
            };

            const struct s2n_signature_scheme *result = NULL;

            if (s2n_is_rsa_pss_signing_supported()) {
                EXPECT_SUCCESS(s2n_choose_sig_scheme_from_peer_preference_list(conn, &peer_list, &result));
                EXPECT_EQUAL(result, &s2n_rsa_pss_rsae_sha256);
            } else {
                EXPECT_FAILURE_WITH_ERRNO(s2n_choose_sig_scheme_from_peer_preference_list(conn, &peer_list, &result),
                        S2N_ERR_INVALID_SIGNATURE_SCHEME);
            }
        };

        s2n_connection_free(conn);
        s2n_config_free(config);
    };

    /* Test fallback of TLS 1.3 signature algorithms */
    if (s2n_is_rsa_pss_signing_supported()) {
        struct s2n_config *config = s2n_config_new();

        struct s2n_connection *conn = s2n_connection_new(S2N_SERVER);
        EXPECT_SUCCESS(s2n_connection_set_config(conn, config));

        const struct s2n_security_policy *security_policy = NULL;
        EXPECT_SUCCESS(s2n_connection_get_security_policy(conn, &security_policy));
        EXPECT_NOT_NULL(security_policy);

        const struct s2n_signature_scheme *const test_rsae_signature_schemes[] = {
            &s2n_rsa_pss_rsae_sha256,
        };

        const struct s2n_signature_preferences test_rsae_preferences = {
            .count = 1,
            .signature_schemes = test_rsae_signature_schemes,
        };

        struct s2n_security_policy test_security_policy = {
            .minimum_protocol_version = security_policy->minimum_protocol_version,
            .cipher_preferences = security_policy->cipher_preferences,
            .kem_preferences = security_policy->kem_preferences,
            .signature_preferences = &test_rsae_preferences,
            .ecc_preferences = security_policy->ecc_preferences,
        };

        config->security_policy = &test_security_policy;

        /* Test: no shared valid signature schemes, using TLS1.3. Server cant pick preferred */
        {
            const struct s2n_signature_scheme *result = NULL;
            conn->secure->cipher_suite = TLS13_CIPHER_SUITE;
            conn->actual_protocol_version = S2N_TLS13;

            struct s2n_sig_scheme_list peer_list = {
                .len = 1,
                .iana_list = {
                        s2n_rsa_pkcs1_sha224.iana_value, /* Invalid (wrong protocol version) */
                },
            };

            EXPECT_FAILURE_WITH_ERRNO(s2n_choose_sig_scheme_from_peer_preference_list(conn, &peer_list, &result),
                    S2N_ERR_INVALID_SIGNATURE_SCHEME);
        };

        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, rsa_cert_chain));

        /* Test: no shared valid signature schemes, using TLS1.3. Server picks a preferred */
        {
            const struct s2n_signature_scheme *result = NULL;
            conn->secure->cipher_suite = TLS13_CIPHER_SUITE;
            conn->actual_protocol_version = S2N_TLS13;

            struct s2n_sig_scheme_list peer_list = {
                .len = 1,
                .iana_list = {
                        s2n_rsa_pkcs1_sha224.iana_value, /* Invalid (wrong protocol version) */
                },
            };

            /* behavior is that we fallback to a preferred signature algorithm */
            EXPECT_SUCCESS(s2n_choose_sig_scheme_from_peer_preference_list(conn, &peer_list, &result));
            EXPECT_EQUAL(result, &s2n_rsa_pss_rsae_sha256);
        };

        s2n_connection_free(conn);
        s2n_config_free(config);
    }

    /* Self-Talk tests: default signature schemes */
    {
        const struct s2n_signature_scheme *const default_schemes[] = {
            &s2n_rsa_pkcs1_sha1,
            &s2n_ecdsa_sha1
        };

        const struct s2n_signature_scheme *const sha256_schemes[] = {
            &s2n_rsa_pkcs1_sha256,
            &s2n_ecdsa_sha256
        };

        const struct s2n_signature_scheme *const sha384_schemes[] = {
            &s2n_rsa_pkcs1_sha384,
            &s2n_ecdsa_sha384
        };

        const struct s2n_signature_preferences defaults_preferences = {
            .count = s2n_array_len(default_schemes),
            .signature_schemes = default_schemes,
        };

        const struct s2n_signature_preferences sha256_preferences = {
            .count = s2n_array_len(sha256_schemes),
            .signature_schemes = sha256_schemes,
        };
        for (size_t i = 0; i < sha256_preferences.count; i++) {
            for (size_t j = 0; j < defaults_preferences.count; j++) {
                EXPECT_NOT_EQUAL(sha256_preferences.signature_schemes[i]->iana_value,
                        defaults_preferences.signature_schemes[j]->iana_value);
            }
        }

        const struct s2n_signature_preferences sha384_preferences = {
            .count = s2n_array_len(sha384_schemes),
            .signature_schemes = sha384_schemes,
        };
        for (size_t i = 0; i < sha384_preferences.count; i++) {
            for (size_t j = 0; j < defaults_preferences.count; j++) {
                EXPECT_NOT_EQUAL(sha384_preferences.signature_schemes[i]->iana_value,
                        defaults_preferences.signature_schemes[j]->iana_value);
            }
        }

        /* The policy needs to negotiate TLS1.2 and forward secret kex */
        struct s2n_security_policy defaults_policy = security_policy_20190214;
        defaults_policy.signature_preferences = &defaults_preferences;
        struct s2n_security_policy sha256_policy = security_policy_20190214;
        sha256_policy.signature_preferences = &sha256_preferences;
        struct s2n_security_policy sha384_policy = security_policy_20190214;
        sha384_policy.signature_preferences = &sha384_preferences;

        /* Self-Talk test: client and server can negotiate without any defaults */
        for (size_t cert_i = 0; cert_i < s2n_array_len(certs); cert_i++) {
            /* Setup config */
            DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
            EXPECT_NOT_NULL(config);
            EXPECT_SUCCESS(s2n_config_set_unsafe_for_testing(config));
            EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, certs[cert_i]));

            /* Setup connections */
            DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT),
                    s2n_connection_ptr_free);
            DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config));
            EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));
            EXPECT_SUCCESS(s2n_connection_set_blinding(client_conn, S2N_SELF_SERVICE_BLINDING));

            /* Create nonblocking pipes */
            DEFER_CLEANUP(struct s2n_test_io_pair io_pair, s2n_io_pair_close);
            EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
            EXPECT_SUCCESS(s2n_connections_set_io_pair(client_conn, server_conn, &io_pair));

            /* Client and server security policies should match but include no defaults */
            client_conn->security_policy_override = &sha256_policy;
            server_conn->security_policy_override = &sha256_policy;

            EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));
            EXPECT_EQUAL(client_conn->actual_protocol_version, S2N_TLS12);
            EXPECT_EQUAL(server_conn->actual_protocol_version, S2N_TLS12);
        };

        /* Self-Talk test: server does not fallback to unsupported defaults */
        for (size_t cert_i = 0; cert_i < s2n_array_len(certs); cert_i++) {
            /* Setup config */
            DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
            EXPECT_NOT_NULL(config);
            EXPECT_SUCCESS(s2n_config_set_unsafe_for_testing(config));
            EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, certs[cert_i]));

            /* Setup connections */
            DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT),
                    s2n_connection_ptr_free);
            DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config));
            EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));
            EXPECT_SUCCESS(s2n_connection_set_blinding(server_conn, S2N_SELF_SERVICE_BLINDING));

            /* Create nonblocking pipes */
            DEFER_CLEANUP(struct s2n_test_io_pair io_pair, s2n_io_pair_close);
            EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
            EXPECT_SUCCESS(s2n_connections_set_io_pair(client_conn, server_conn, &io_pair));

            /* Client and server security policies should have no signature schemes
             * in common, and not include the default signature schemes.
             */
            client_conn->security_policy_override = &sha256_policy;
            server_conn->security_policy_override = &sha384_policy;

            EXPECT_FAILURE_WITH_ERRNO(s2n_negotiate_test_server_and_client(server_conn, client_conn),
                    S2N_ERR_INVALID_SIGNATURE_ALGORITHM);
            EXPECT_EQUAL(client_conn->actual_protocol_version, S2N_TLS12);
            EXPECT_EQUAL(server_conn->actual_protocol_version, S2N_TLS12);
        };

        /* Self-Talk test: client does not accept unsupported defaults */
        for (size_t cert_i = 0; cert_i < s2n_array_len(certs); cert_i++) {
            DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
            EXPECT_NOT_NULL(config);
            EXPECT_SUCCESS(s2n_config_set_unsafe_for_testing(config));
            EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, certs[cert_i]));

            /* Setup connections */
            DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT),
                    s2n_connection_ptr_free);
            DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config));
            EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));
            EXPECT_SUCCESS(s2n_connection_set_blinding(client_conn, S2N_SELF_SERVICE_BLINDING));

            /* Create nonblocking pipes */
            DEFER_CLEANUP(struct s2n_test_io_pair io_pair, s2n_io_pair_close);
            EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
            EXPECT_SUCCESS(s2n_connections_set_io_pair(client_conn, server_conn, &io_pair));

            /* Client and server security policies should have no signature schemes in common.
             * Server should include the default policies.
             */
            client_conn->security_policy_override = &sha256_policy;
            server_conn->security_policy_override = &defaults_policy;

            EXPECT_FAILURE_WITH_ERRNO(s2n_negotiate_test_server_and_client(server_conn, client_conn),
                    S2N_ERR_INVALID_SIGNATURE_SCHEME);
            EXPECT_EQUAL(client_conn->actual_protocol_version, S2N_TLS12);
            EXPECT_EQUAL(server_conn->actual_protocol_version, S2N_TLS12);
        };
    };

    EXPECT_SUCCESS(s2n_cert_chain_and_key_free(rsa_cert_chain));
    EXPECT_SUCCESS(s2n_cert_chain_and_key_free(ecdsa_cert_chain));

    END_TEST();

    return 0;
}
