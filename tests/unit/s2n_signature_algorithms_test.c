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

#include <s2n.h>

#include "s2n_test.h"
#include "testlib/s2n_testlib.h"

#include "crypto/s2n_fips.h"
#include "crypto/s2n_rsa_pss.h"

#include "tls/s2n_cipher_suites.h"
#include "tls/s2n_config.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_signature_scheme.h"
#include "tls/s2n_signature_algorithms.h"
#include "tls/s2n_security_policies.h"

#define LENGTH 3
#define STUFFER_SIZE (LENGTH * TLS_SIGNATURE_SCHEME_LEN + 10)

#define RSA_CIPHER_SUITE &s2n_rsa_with_rc4_128_md5
#define ECDSA_CIPHER_SUITE &s2n_ecdhe_ecdsa_with_aes_128_cbc_sha
#define TLS13_CIPHER_SUITE &s2n_tls13_aes_128_gcm_sha256

const struct s2n_signature_scheme *const test_signature_schemes[] = {
        &s2n_ecdsa_secp384r1_sha384,
        &s2n_rsa_pkcs1_sha256,
        &s2n_rsa_pkcs1_sha224,
};

const struct s2n_signature_preferences test_preferences = {
        .count = LENGTH,
        .signature_schemes = test_signature_schemes,
};

int main(int argc, char **argv)
{
    BEGIN_TEST();

    struct s2n_cert_chain_and_key *rsa_cert_chain;
    EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&rsa_cert_chain,
            S2N_DEFAULT_TEST_CERT_CHAIN, S2N_DEFAULT_TEST_PRIVATE_KEY));

    struct s2n_cert_chain_and_key *ecdsa_cert_chain;
    EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&ecdsa_cert_chain,
            S2N_ECDSA_P384_PKCS1_CERT_CHAIN, S2N_ECDSA_P384_PKCS1_KEY));

    /* s2n_supported_sig_schemes_count & s2n_supported_sig_scheme_list_size */
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

        /* Test: if all signatures supported, count all signatures */
        {
            conn->actual_protocol_version = S2N_TLS13;
            EXPECT_EQUAL(s2n_supported_sig_schemes_count(conn), LENGTH);
            EXPECT_EQUAL(s2n_supported_sig_scheme_list_size(conn), LENGTH * TLS_SIGNATURE_SCHEME_LEN);
        }

        /* Test: if some signatures are not supported, exclude them from the count */
        {
            conn->actual_protocol_version = S2N_TLS10;
            /* Do not include s2n_ecdsa_secp384r1_sha384, which has a minimum version of tls13 */
            EXPECT_EQUAL(s2n_supported_sig_schemes_count(conn), LENGTH - 1);
            EXPECT_EQUAL(s2n_supported_sig_scheme_list_size(conn), (LENGTH - 1) * TLS_SIGNATURE_SCHEME_LEN);
        }

        s2n_connection_free(conn);
        s2n_config_free(config);
    }

    /* s2n_send_supported_sig_scheme_list */
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

        struct s2n_stuffer result;
        s2n_stuffer_growable_alloc(&result, STUFFER_SIZE);

        uint16_t size, iana_value;

        /* Test: if all signatures supported, send all signatures */
        {
            s2n_stuffer_wipe(&result);

            conn->actual_protocol_version = S2N_TLS13;
            EXPECT_SUCCESS(s2n_send_supported_sig_scheme_list(conn, &result));

            EXPECT_SUCCESS(s2n_stuffer_read_uint16(&result, &size));
            EXPECT_EQUAL(size, s2n_supported_sig_scheme_list_size(conn));

            for (int i = 0; i < LENGTH; i++) {
                EXPECT_SUCCESS(s2n_stuffer_read_uint16(&result, &iana_value));
                EXPECT_EQUAL(iana_value, test_signature_schemes[i]->iana_value);
            }

            EXPECT_EQUAL(s2n_stuffer_data_available(&result), 0);
        }

        /* Test: do not send unsupported signatures */
        {
            s2n_stuffer_wipe(&result);

            conn->actual_protocol_version = S2N_TLS12;
            EXPECT_SUCCESS(s2n_send_supported_sig_scheme_list(conn, &result));

            EXPECT_SUCCESS(s2n_stuffer_read_uint16(&result, &size));
            EXPECT_EQUAL(size, s2n_supported_sig_scheme_list_size(conn));

            for (int i = 0; i < LENGTH; i++) {
                if (test_signature_schemes[i] != &s2n_ecdsa_secp384r1_sha384) {
                    EXPECT_SUCCESS(s2n_stuffer_read_uint16(&result, &iana_value));
                    EXPECT_EQUAL(iana_value, test_signature_schemes[i]->iana_value);
                }
            }

            EXPECT_EQUAL(s2n_stuffer_data_available(&result), 0);
        }

        /* Test: written signatures readable */
        {
            s2n_stuffer_wipe(&result);
            conn->actual_protocol_version = S2N_TLS13;

            struct s2n_sig_scheme_list signatures;

            EXPECT_SUCCESS(s2n_send_supported_sig_scheme_list(conn, &result));
            EXPECT_SUCCESS(s2n_recv_supported_sig_scheme_list(&result, &signatures));
            EXPECT_EQUAL(s2n_stuffer_data_available(&result), 0);

            EXPECT_EQUAL(signatures.len, LENGTH);
            for (int i=0; i < LENGTH; i++) {
                EXPECT_EQUAL(signatures.iana_list[i], test_signature_schemes[i]->iana_value);
            }
        }

        s2n_connection_free(conn);
        s2n_config_free(config);
        s2n_stuffer_free(&result);
    }

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

        struct s2n_stuffer choice;
        s2n_stuffer_growable_alloc(&choice, STUFFER_SIZE);

        struct s2n_signature_scheme result;

        /* Test: successfully choose valid signature */
        {
            s2n_stuffer_wipe(&choice);
            s2n_stuffer_write_uint16(&choice, s2n_rsa_pkcs1_sha256.iana_value);

            EXPECT_SUCCESS(s2n_get_and_validate_negotiated_signature_scheme(conn, &choice, &result));
            EXPECT_EQUAL(result.iana_value, s2n_rsa_pkcs1_sha256.iana_value);
            EXPECT_BYTEARRAY_EQUAL(&result, &s2n_rsa_pkcs1_sha256, sizeof(struct s2n_signature_scheme));
        }

        /* Test: don't negotiate invalid signatures (protocol not high enough) */
        {
            s2n_stuffer_wipe(&choice);
            s2n_stuffer_write_uint16(&choice, s2n_ecdsa_secp384r1_sha384.iana_value);

            conn->actual_protocol_version = S2N_TLS13;
            EXPECT_SUCCESS(s2n_get_and_validate_negotiated_signature_scheme(conn, &choice, &result));
            EXPECT_EQUAL(result.iana_value, s2n_ecdsa_secp384r1_sha384.iana_value);
            EXPECT_BYTEARRAY_EQUAL(&result, &s2n_ecdsa_secp384r1_sha384, sizeof(struct s2n_signature_scheme));

            s2n_stuffer_reread(&choice);
            conn->actual_protocol_version = S2N_TLS12;
            EXPECT_FAILURE_WITH_ERRNO(s2n_get_and_validate_negotiated_signature_scheme(conn, &choice, &result),
                    S2N_ERR_INVALID_SIGNATURE_SCHEME);
        }

        /* Test: don't negotiate invalid signatures (protocol too high) */
        {
            s2n_stuffer_wipe(&choice);
            s2n_stuffer_write_uint16(&choice, s2n_rsa_pkcs1_sha224.iana_value);

            conn->actual_protocol_version = S2N_TLS12;
            EXPECT_SUCCESS(s2n_get_and_validate_negotiated_signature_scheme(conn, &choice, &result));
            EXPECT_EQUAL(result.iana_value, s2n_rsa_pkcs1_sha224.iana_value);
            EXPECT_BYTEARRAY_EQUAL(&result, &s2n_rsa_pkcs1_sha224, sizeof(struct s2n_signature_scheme));

            s2n_stuffer_reread(&choice);
            conn->actual_protocol_version = S2N_TLS13;
            EXPECT_FAILURE_WITH_ERRNO(s2n_get_and_validate_negotiated_signature_scheme(conn, &choice, &result),
                    S2N_ERR_INVALID_SIGNATURE_SCHEME);
        }

        s2n_connection_free(conn);
        s2n_config_free(config);
        s2n_stuffer_free(&choice);
    }


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

        struct s2n_stuffer choice;
        s2n_stuffer_growable_alloc(&choice, STUFFER_SIZE);

        struct s2n_signature_scheme result;

        conn->actual_protocol_version = S2N_TLS13;
        s2n_stuffer_write_uint16(&choice, s2n_ecdsa_sha384.iana_value);
        EXPECT_SUCCESS(s2n_get_and_validate_negotiated_signature_scheme(conn, &choice, &result));
        EXPECT_EQUAL(result.iana_value, s2n_ecdsa_secp384r1_sha384.iana_value);
        EXPECT_BYTEARRAY_EQUAL(&result, &s2n_ecdsa_secp384r1_sha384, sizeof(struct s2n_signature_scheme));

        conn->actual_protocol_version = S2N_TLS12;
        s2n_stuffer_write_uint16(&choice, s2n_ecdsa_sha384.iana_value);
        EXPECT_SUCCESS(s2n_get_and_validate_negotiated_signature_scheme(conn, &choice, &result));
        EXPECT_EQUAL(result.iana_value, s2n_ecdsa_sha384.iana_value);
        EXPECT_BYTEARRAY_EQUAL(&result, &s2n_ecdsa_sha384, sizeof(struct s2n_signature_scheme));

        s2n_connection_free(conn);
        s2n_config_free(config);
        s2n_stuffer_free(&choice);
    }

    /* s2n_choose_default_sig_scheme */
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

        struct s2n_signature_scheme result;

        conn->secure.cipher_suite = RSA_CIPHER_SUITE;
        conn->actual_protocol_version = S2N_TLS10;
        struct s2n_signature_scheme expected = (s2n_is_in_fips_mode()) ? s2n_rsa_pkcs1_sha1 : s2n_rsa_pkcs1_md5_sha1;
        EXPECT_SUCCESS(s2n_choose_default_sig_scheme(conn, &result));
        EXPECT_EQUAL(result.iana_value, expected.iana_value);

        conn->secure.cipher_suite = ECDSA_CIPHER_SUITE;
        conn->actual_protocol_version = S2N_TLS10;
        EXPECT_SUCCESS(s2n_choose_default_sig_scheme(conn, &result));
        EXPECT_EQUAL(result.iana_value, s2n_ecdsa_sha1.iana_value);

        conn->secure.cipher_suite = RSA_CIPHER_SUITE;
        conn->actual_protocol_version = S2N_TLS12;
        EXPECT_SUCCESS(s2n_choose_default_sig_scheme(conn, &result));
        EXPECT_EQUAL(result.iana_value, s2n_rsa_pkcs1_sha1.iana_value);

        s2n_connection_free(conn);
        s2n_config_free(config);
    }

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

        struct s2n_signature_scheme result;

        /* Test: no peer list */
        {
            conn->secure.cipher_suite = ECDSA_CIPHER_SUITE;
            conn->actual_protocol_version = S2N_TLS10;
            struct s2n_signature_scheme default_scheme = s2n_ecdsa_sha1;

            /* Choose default if NULL peer list */
            EXPECT_SUCCESS(s2n_choose_sig_scheme_from_peer_preference_list(conn, NULL, &result));
            EXPECT_EQUAL(result.iana_value, default_scheme.iana_value);

            /* Choose default if empty peer list */
            struct s2n_sig_scheme_list peer_list = {
                    .len = 0,
                    .iana_list = { 0 },
            };
            EXPECT_SUCCESS(s2n_choose_sig_scheme_from_peer_preference_list(conn, &peer_list, &result));
            EXPECT_EQUAL(result.iana_value, default_scheme.iana_value);

            /* If we cannot find a match in TLS1.3, allow defaults for success */
            conn->secure.cipher_suite = TLS13_CIPHER_SUITE;
            conn->actual_protocol_version = S2N_TLS13;
            EXPECT_SUCCESS(s2n_choose_sig_scheme_from_peer_preference_list(conn, &peer_list, &result));
        }

        /* Test: no shared valid signature schemes, using TLS1.3. Server picks preferred */
        {
            conn->secure.cipher_suite = TLS13_CIPHER_SUITE;
            conn->actual_protocol_version = S2N_TLS13;

            struct s2n_sig_scheme_list peer_list = {
                    .len = 2, .iana_list = {
                            s2n_rsa_pkcs1_sha224.iana_value, /* Invalid (wrong protocol version) */
                            s2n_rsa_pkcs1_sha1.iana_value, /* Not in preference list */
                    },
            };

            /* behavior is that we fallback to a preferred signature algorithm */
            EXPECT_SUCCESS(s2n_choose_sig_scheme_from_peer_preference_list(conn, &peer_list, &result));
            EXPECT_EQUAL(result.iana_value, s2n_ecdsa_sha384.iana_value);
        }

        /* Test: no shared valid signature schemes, using TLS1.2 */
        {
            conn->secure.cipher_suite = TLS13_CIPHER_SUITE;
            conn->actual_protocol_version = S2N_TLS12;

            /* Peer list contains no signature schemes that we support */
            struct s2n_sig_scheme_list peer_list = {
                    .len = 1, .iana_list = { 0 },
            };

            EXPECT_SUCCESS(s2n_choose_sig_scheme_from_peer_preference_list(conn, &peer_list, &result));

            /* Verify that we did not choose the peer's offered signature scheme */
            EXPECT_NOT_EQUAL(result.iana_value, peer_list.iana_list[0]);

            /* Verify that we chose the default signature scheme, even though it wasn't in
             * the peer's offered list. This proves that when we share no signature schemes
             * with the peer, then calling s2n_choose_sig_scheme_from_peer_preference_list
             * is equivalent to calling s2n_choose_default_sig_scheme. */
            struct s2n_signature_scheme default_scheme;
            EXPECT_SUCCESS(s2n_choose_default_sig_scheme(conn, &default_scheme));
            EXPECT_EQUAL(result.iana_value, default_scheme.iana_value);
        }

        /* Test: choose valid signature from peer list */
        {
            conn->secure.cipher_suite = RSA_CIPHER_SUITE;
            conn->actual_protocol_version = S2N_TLS12;

            struct s2n_sig_scheme_list peer_list = {
                    .len = 4, .iana_list = {
                            s2n_ecdsa_secp384r1_sha384.iana_value, /* Invalid: wrong protocol, wrong auth method */
                            s2n_rsa_pkcs1_sha1.iana_value,  /* Invalid: not in preference list */
                            s2n_rsa_pkcs1_sha256.iana_value, /* Valid -- should be chosen */
                            s2n_rsa_pkcs1_sha224.iana_value, /* Valid, but lower priority -- should not be chosen */
                    },
            };

            EXPECT_SUCCESS(s2n_choose_sig_scheme_from_peer_preference_list(conn, &peer_list, &result));
            EXPECT_EQUAL(result.iana_value, s2n_rsa_pkcs1_sha256.iana_value);
            EXPECT_BYTEARRAY_EQUAL(&result, &s2n_rsa_pkcs1_sha256, sizeof(struct s2n_signature_scheme));
        }

        /* Test: invalid scheme, because wrong protocol version */
        {
            conn->secure.cipher_suite = RSA_CIPHER_SUITE;

            struct s2n_sig_scheme_list peer_list = {
                    .len = 1, .iana_list = { s2n_rsa_pkcs1_sha224.iana_value },
            };

            conn->actual_protocol_version = S2N_TLS12;
            EXPECT_SUCCESS(s2n_choose_sig_scheme_from_peer_preference_list(conn, &peer_list, &result));
            EXPECT_EQUAL(result.iana_value, s2n_rsa_pkcs1_sha224.iana_value);
            EXPECT_BYTEARRAY_EQUAL(&result, &s2n_rsa_pkcs1_sha224, sizeof(struct s2n_signature_scheme));

            conn->actual_protocol_version = S2N_TLS13;
            EXPECT_FAILURE_WITH_ERRNO(s2n_choose_sig_scheme_from_peer_preference_list(conn, &peer_list, &result),
                    S2N_ERR_INVALID_SIGNATURE_SCHEME);
        }

        s2n_connection_free(conn);
        s2n_config_free(config);
    }

    /* Test: send and receive default signature preferences */
    {
        struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT);

        struct s2n_stuffer result;
        s2n_stuffer_growable_alloc(&result, STUFFER_SIZE);

        struct s2n_sig_scheme_list signatures;

        for (int i = S2N_TLS10; i < S2N_TLS13; i++) {
            s2n_stuffer_wipe(&result);
            conn->actual_protocol_version = i;

            EXPECT_SUCCESS(s2n_send_supported_sig_scheme_list(conn, &result));
            EXPECT_SUCCESS(s2n_recv_supported_sig_scheme_list(&result, &signatures));
            EXPECT_EQUAL(s2n_stuffer_data_available(&result), 0);

            EXPECT_EQUAL(signatures.len, s2n_supported_sig_schemes_count(conn));

            /* Verify no duplicates - some preferences contain duplicates, but only
             * one should be valid at a time. */
            uint16_t iana, other_iana;
            for (int a = 0; a < signatures.len; a++) {
                iana = signatures.iana_list[a];
                for (int b = 0; b < signatures.len; b++) {
                    if (a == b) {
                        continue;
                    }
                    other_iana = signatures.iana_list[b];
                    EXPECT_NOT_EQUAL(iana, other_iana);
                }
            }
        }

        s2n_connection_free(conn);
        s2n_stuffer_free(&result);
    }

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
        conn->secure.cipher_suite = TLS13_CIPHER_SUITE;
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
         * s2n_send_supported_sig_scheme_list + PSS */
        {
            struct s2n_stuffer result;
            s2n_stuffer_growable_alloc(&result, STUFFER_SIZE);

            EXPECT_SUCCESS(s2n_send_supported_sig_scheme_list(conn, &result));

            uint16_t size;
            EXPECT_SUCCESS(s2n_stuffer_read_uint16(&result, &size));
            EXPECT_EQUAL(size, s2n_supported_sig_scheme_list_size(conn));
            if (s2n_is_rsa_pss_certs_supported()) {
                EXPECT_EQUAL(size, 2 * sizeof(uint16_t));
            }  else if (s2n_is_rsa_pss_signing_supported()) {
                EXPECT_EQUAL(size, 1 * sizeof(uint16_t));
            } else {
                EXPECT_EQUAL(size, 0);
            }

            s2n_stuffer_free(&result);
        }

        /* Do not accept a PSS signature scheme if unsupported:
         * s2n_get_and_validate_negotiated_signature_scheme + PSS */
        {
            struct s2n_stuffer choice;
            s2n_stuffer_growable_alloc(&choice, STUFFER_SIZE);
            s2n_stuffer_write_uint16(&choice, s2n_rsa_pss_rsae_sha256.iana_value);

            struct s2n_signature_scheme result;

            if (s2n_is_rsa_pss_signing_supported()) {
                EXPECT_SUCCESS(s2n_get_and_validate_negotiated_signature_scheme(conn, &choice, &result));
                EXPECT_EQUAL(result.iana_value, s2n_rsa_pss_rsae_sha256.iana_value);
            } else {
                EXPECT_FAILURE_WITH_ERRNO(s2n_get_and_validate_negotiated_signature_scheme(conn, &choice, &result),
                        S2N_ERR_INVALID_SIGNATURE_SCHEME);
            }

            s2n_stuffer_free(&choice);
        }

        /* Do not choose a PSS signature scheme if unsupported:
         * s2n_choose_sig_scheme_from_peer_preference_list + PSS */
        {
            struct s2n_sig_scheme_list peer_list = {
                    .len = 1, .iana_list = { s2n_rsa_pss_rsae_sha256.iana_value },
            };

            struct s2n_signature_scheme result;

            if (s2n_is_rsa_pss_signing_supported()) {
                EXPECT_SUCCESS(s2n_choose_sig_scheme_from_peer_preference_list(conn, &peer_list, &result));
                EXPECT_EQUAL(result.iana_value, s2n_rsa_pss_rsae_sha256.iana_value);
            } else {
                EXPECT_FAILURE_WITH_ERRNO(s2n_choose_sig_scheme_from_peer_preference_list(conn, &peer_list, &result),
                        S2N_ERR_INVALID_SIGNATURE_SCHEME);
            }
        }

        s2n_connection_free(conn);
        s2n_config_free(config);
    }

    /* Test fallback of TLS 1.3 signature algorithms */
    if (s2n_is_rsa_pss_signing_supported())
    {
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

        struct s2n_signature_scheme result;

        /* Test: no shared valid signature schemes, using TLS1.3. Server cant pick preferred */
        {
            conn->secure.cipher_suite = TLS13_CIPHER_SUITE;
            conn->actual_protocol_version = S2N_TLS13;

            struct s2n_sig_scheme_list peer_list = {
                    .len = 1, .iana_list = {
                        s2n_rsa_pkcs1_sha224.iana_value, /* Invalid (wrong protocol version) */
                    },
            };

            EXPECT_FAILURE_WITH_ERRNO(s2n_choose_sig_scheme_from_peer_preference_list(conn, &peer_list, &result),
                S2N_ERR_INVALID_SIGNATURE_SCHEME);
        }

        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, rsa_cert_chain));

        /* Test: no shared valid signature schemes, using TLS1.3. Server picks a preferred */
        {
            conn->secure.cipher_suite = TLS13_CIPHER_SUITE;
            conn->actual_protocol_version = S2N_TLS13;

            struct s2n_sig_scheme_list peer_list = {
                    .len = 1, .iana_list = {
                        s2n_rsa_pkcs1_sha224.iana_value, /* Invalid (wrong protocol version) */
                    },
            };

            /* behavior is that we fallback to a preferred signature algorithm */
            EXPECT_SUCCESS(s2n_choose_sig_scheme_from_peer_preference_list(conn, &peer_list, &result));
            EXPECT_EQUAL(result.iana_value, s2n_rsa_pss_rsae_sha256.iana_value);
        }

        s2n_connection_free(conn);
        s2n_config_free(config);
    }

    EXPECT_SUCCESS(s2n_cert_chain_and_key_free(rsa_cert_chain));
    EXPECT_SUCCESS(s2n_cert_chain_and_key_free(ecdsa_cert_chain));

    END_TEST();

    return 0;
}
