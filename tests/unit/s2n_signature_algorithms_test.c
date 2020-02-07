/*
 * Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

#include "tls/s2n_cipher_suites.h"
#include "tls/s2n_config.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_signature_scheme.h"
#include "tls/s2n_signature_algorithms.h"

#define LENGTH 3
#define STUFFER_SIZE (LENGTH * TLS_SIGNATURE_SCHEME_LEN + 10)

#define RSA_CIPHER_SUITE &s2n_rsa_with_rc4_128_md5
#define ECDSA_CIPHER_SUITE &s2n_ecdhe_ecdsa_with_aes_128_cbc_sha

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

    char rsa_certs[S2N_MAX_TEST_PEM_SIZE], rsa_private_key[S2N_MAX_TEST_PEM_SIZE];
    EXPECT_SUCCESS(s2n_read_test_pem(S2N_RSA_2048_PKCS1_CERT_CHAIN, rsa_certs, S2N_MAX_TEST_PEM_SIZE));
    EXPECT_SUCCESS(s2n_read_test_pem(S2N_RSA_2048_PKCS1_KEY, rsa_private_key, S2N_MAX_TEST_PEM_SIZE));

    struct s2n_cert_chain_and_key *rsa_cert_chain;
    EXPECT_NOT_NULL(rsa_cert_chain = s2n_cert_chain_and_key_new());
    EXPECT_SUCCESS(s2n_cert_chain_and_key_load_pem(rsa_cert_chain, rsa_certs, rsa_private_key));

    char ecdsa_certs[S2N_MAX_TEST_PEM_SIZE], ecdsa_private_key[S2N_MAX_TEST_PEM_SIZE];
    EXPECT_SUCCESS(s2n_read_test_pem(S2N_ECDSA_P384_PKCS1_CERT_CHAIN, ecdsa_certs, S2N_MAX_TEST_PEM_SIZE));
    EXPECT_SUCCESS(s2n_read_test_pem(S2N_ECDSA_P384_PKCS1_KEY, ecdsa_private_key, S2N_MAX_TEST_PEM_SIZE));

    struct s2n_cert_chain_and_key *ecdsa_cert_chain;
    EXPECT_NOT_NULL(ecdsa_cert_chain = s2n_cert_chain_and_key_new());
    EXPECT_SUCCESS(s2n_cert_chain_and_key_load_pem(ecdsa_cert_chain, ecdsa_certs, ecdsa_private_key));

    /* s2n_supported_sig_schemes_count & s2n_supported_sig_scheme_list_size */
    {
        struct s2n_config *config = s2n_config_new();
        config->signature_preferences = &test_preferences;

        struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT);
        s2n_connection_set_config(conn, config);

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
        config->signature_preferences = &test_preferences;

        struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT);
        s2n_connection_set_config(conn, config);

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

            for (int i=0; i < LENGTH; i++) {
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

            for (int i=0; i < LENGTH; i++) {
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
        config->signature_preferences = &test_preferences;

        struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT);
        s2n_connection_set_config(conn, config);

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
        config->signature_preferences = &dup_test_preferences;

        struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT);
        s2n_connection_set_config(conn, config);

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

    /* s2n_choose_sig_scheme_from_peer_preference_list */
    {
        struct s2n_config *config = s2n_config_new();
        config->signature_preferences = &test_preferences;

        struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT);
        s2n_connection_set_config(conn, config);

        struct s2n_signature_scheme result;

        /* Test: choose defaults */
        {
            struct s2n_sig_scheme_list peer_list = {
                    .len = 0,
                    .iana_list = { 0 },
            };

            conn->secure.cipher_suite = RSA_CIPHER_SUITE;
            conn->actual_protocol_version = S2N_TLS10;
            struct s2n_signature_scheme expected = (s2n_is_in_fips_mode()) ? s2n_rsa_pkcs1_sha1 : s2n_rsa_pkcs1_md5_sha1;
            EXPECT_SUCCESS(s2n_choose_sig_scheme_from_peer_preference_list(conn, &peer_list, &result));
            EXPECT_EQUAL(result.iana_value, expected.iana_value);
            EXPECT_BYTEARRAY_EQUAL(&result, &expected, sizeof(struct s2n_signature_scheme));

            conn->secure.cipher_suite = ECDSA_CIPHER_SUITE;
            conn->actual_protocol_version = S2N_TLS10;
            EXPECT_SUCCESS(s2n_choose_sig_scheme_from_peer_preference_list(conn, &peer_list, &result));
            EXPECT_EQUAL(result.iana_value, s2n_ecdsa_sha1.iana_value);
            EXPECT_BYTEARRAY_EQUAL(&result, &s2n_ecdsa_sha1, sizeof(struct s2n_signature_scheme));

            conn->secure.cipher_suite = RSA_CIPHER_SUITE;
            conn->actual_protocol_version = S2N_TLS12;
            EXPECT_SUCCESS(s2n_choose_sig_scheme_from_peer_preference_list(conn, &peer_list, &result));
            EXPECT_EQUAL(result.iana_value, s2n_rsa_pkcs1_sha1.iana_value);
            EXPECT_BYTEARRAY_EQUAL(&result, &s2n_rsa_pkcs1_sha1, sizeof(struct s2n_signature_scheme));

            /* TLS1.3 does not allow defaults */
            conn->actual_protocol_version = S2N_TLS13;
            EXPECT_FAILURE_WITH_ERRNO(s2n_choose_sig_scheme_from_peer_preference_list(conn, &peer_list, &result),
                    S2N_ERR_EMPTY_SIGNATURE_SCHEME);
        }

        /* Test: no shared valid signature schemes */
        {
            conn->secure.cipher_suite = RSA_CIPHER_SUITE;
            conn->actual_protocol_version = S2N_TLS13;

            struct s2n_sig_scheme_list peer_list = {
                    .len = 2, .iana_list = {
                            s2n_rsa_pkcs1_sha224.iana_value, /* Invalid (wrong protocol version) */
                            s2n_rsa_pkcs1_sha1.iana_value, /* Not in preference list */
                    },
            };

            EXPECT_FAILURE_WITH_ERRNO(s2n_choose_sig_scheme_from_peer_preference_list(conn, &peer_list, &result),
                    S2N_ERR_INVALID_SIGNATURE_SCHEME);
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
                    .len = 2, .iana_list = { s2n_rsa_pkcs1_sha224.iana_value },
            };

            conn->actual_protocol_version = S2N_TLS12;
            EXPECT_SUCCESS(s2n_choose_sig_scheme_from_peer_preference_list(conn, &peer_list, &result));
            EXPECT_EQUAL(result.iana_value, s2n_rsa_pkcs1_sha224.iana_value);
            EXPECT_BYTEARRAY_EQUAL(&result, &s2n_rsa_pkcs1_sha224, sizeof(struct s2n_signature_scheme));

            conn->actual_protocol_version = S2N_TLS13;
            EXPECT_FAILURE_WITH_ERRNO(s2n_choose_sig_scheme_from_peer_preference_list(conn, &peer_list, &result),
                    S2N_ERR_INVALID_SIGNATURE_SCHEME);
        }

        /* Test: invalid scheme, because incorrect auth method  */
        {
            conn->actual_protocol_version = S2N_TLS12;

            struct s2n_sig_scheme_list peer_list = {
                    .len = 1, .iana_list = { s2n_rsa_pkcs1_sha224.iana_value },
            };

            conn->secure.cipher_suite = RSA_CIPHER_SUITE;
            EXPECT_SUCCESS(s2n_choose_sig_scheme_from_peer_preference_list(conn, &peer_list, &result));
            EXPECT_EQUAL(result.iana_value, s2n_rsa_pkcs1_sha224.iana_value);
            EXPECT_BYTEARRAY_EQUAL(&result, &s2n_rsa_pkcs1_sha224, sizeof(struct s2n_signature_scheme));

            conn->secure.cipher_suite = ECDSA_CIPHER_SUITE;
            EXPECT_FAILURE_WITH_ERRNO(s2n_choose_sig_scheme_from_peer_preference_list(conn, &peer_list, &result),
                    S2N_ERR_INVALID_SIGNATURE_SCHEME);
        }

        /* Test: invalid scheme, because no matching cert (tls1.3 only) */
        {
            conn->secure.cipher_suite = RSA_CIPHER_SUITE;
            struct s2n_sig_scheme_list peer_list = {
                    .len = 2, .iana_list = {
                            s2n_ecdsa_secp384r1_sha384.iana_value,
                            s2n_rsa_pkcs1_sha256.iana_value },
            };

            conn->actual_protocol_version = S2N_TLS13;
            EXPECT_FAILURE_WITH_ERRNO(s2n_choose_sig_scheme_from_peer_preference_list(conn, &peer_list, &result),
                    S2N_ERR_INVALID_SIGNATURE_SCHEME);

            conn->actual_protocol_version = S2N_TLS12;
            EXPECT_SUCCESS(s2n_choose_sig_scheme_from_peer_preference_list(conn, &peer_list, &result));
            EXPECT_EQUAL(result.iana_value, s2n_rsa_pkcs1_sha256.iana_value);
            EXPECT_BYTEARRAY_EQUAL(&result, &s2n_rsa_pkcs1_sha256, sizeof(struct s2n_signature_scheme));

            conn->actual_protocol_version = S2N_TLS13;

            EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, rsa_cert_chain));
            EXPECT_SUCCESS(s2n_choose_sig_scheme_from_peer_preference_list(conn, &peer_list, &result));
            EXPECT_EQUAL(result.iana_value, s2n_rsa_pkcs1_sha256.iana_value);
            EXPECT_BYTEARRAY_EQUAL(&result, &s2n_rsa_pkcs1_sha256, sizeof(struct s2n_signature_scheme));

            EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, ecdsa_cert_chain));
            EXPECT_SUCCESS(s2n_choose_sig_scheme_from_peer_preference_list(conn, &peer_list, &result));
            EXPECT_EQUAL(result.iana_value, s2n_ecdsa_secp384r1_sha384.iana_value);
            EXPECT_BYTEARRAY_EQUAL(&result, &s2n_ecdsa_secp384r1_sha384, sizeof(struct s2n_signature_scheme));
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

        for (int i=S2N_TLS10; i < S2N_TLS13; i++) {
            s2n_stuffer_wipe(&result);
            conn->actual_protocol_version = i;

            EXPECT_SUCCESS(s2n_send_supported_sig_scheme_list(conn, &result));
            EXPECT_SUCCESS(s2n_recv_supported_sig_scheme_list(&result, &signatures));
            EXPECT_EQUAL(s2n_stuffer_data_available(&result), 0);

            EXPECT_EQUAL(signatures.len, s2n_supported_sig_schemes_count(conn));

            /* Verify no duplicates - some preferences contain duplicates, but only
             * one should be valid at a time. */
            uint16_t iana, other_iana;
            for (int a=0; a < signatures.len; a++) {
                iana = signatures.iana_list[a];
                for (int b=0; b < signatures.len; b++) {
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

    EXPECT_SUCCESS(s2n_cert_chain_and_key_free(rsa_cert_chain));
    EXPECT_SUCCESS(s2n_cert_chain_and_key_free(ecdsa_cert_chain));

    END_TEST();

    return 0;
}
