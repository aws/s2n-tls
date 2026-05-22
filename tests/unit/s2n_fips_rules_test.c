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

#include "crypto/s2n_fips.h"
#include "s2n_test.h"
#include "testlib/s2n_testlib.h"

S2N_RESULT s2n_fips_validate_hash_algorithm(s2n_hash_algorithm hash_alg, bool *valid);

int main(int argc, char **argv)
{
    BEGIN_TEST();

    /* Test s2n_fips_validate_cipher_suite */
    {
        /* Safety */
        {
            bool is_valid = false;
            EXPECT_ERROR_WITH_ERRNO(
                    s2n_fips_validate_cipher_suite(NULL, &is_valid),
                    S2N_ERR_NULL);
            EXPECT_ERROR_WITH_ERRNO(
                    s2n_fips_validate_cipher_suite(&s2n_null_cipher_suite, NULL),
                    S2N_ERR_NULL);
        }

        /* Test: Valid */
        const struct s2n_cipher_suite *valid[] = {
            &s2n_tls13_aes_256_gcm_sha384,
            &s2n_ecdhe_rsa_with_aes_128_gcm_sha256,
            &s2n_ecdhe_rsa_with_aes_256_cbc_sha384,
        };
        for (size_t i = 0; i < s2n_array_len(valid); i++) {
            bool is_valid = false;
            EXPECT_OK(s2n_fips_validate_cipher_suite(valid[i], &is_valid));
            EXPECT_TRUE(is_valid);
        }

        /* Test: Invalid */
        const struct s2n_cipher_suite *invalid[] = {
            &s2n_null_cipher_suite,
            &s2n_rsa_with_rc4_128_md5,
            &s2n_rsa_with_aes_128_gcm_sha256,
        };
        for (size_t i = 0; i < s2n_array_len(invalid); i++) {
            bool is_valid = true;
            EXPECT_OK(s2n_fips_validate_cipher_suite(invalid[i], &is_valid));
            EXPECT_FALSE(is_valid);
        }

        /* Test: check all */
        for (size_t i = 0; i < cipher_preferences_test_all.count; i++) {
            const struct s2n_cipher_suite *cipher_suite = cipher_preferences_test_all.suites[i];

            bool is_valid = false;
            EXPECT_OK(s2n_fips_validate_cipher_suite(cipher_suite, &is_valid));
            if (!is_valid) {
                continue;
            }

            /* Must be in the "test_all_fips" security policy */
            const struct s2n_cipher_preferences *test_all_fips_prefs =
                    security_policy_test_all_fips.cipher_preferences;
            bool is_in_test_all_fips_prefs = false;
            for (size_t j = 0; j < test_all_fips_prefs->count; j++) {
                if (cipher_suite == test_all_fips_prefs->suites[j]) {
                    is_in_test_all_fips_prefs = true;
                }
            }
            EXPECT_TRUE(is_in_test_all_fips_prefs);

            /* We copy our lists of allowed cipher suites directly from the standards,
             * but we should double check any invariants we can just in case.
             */

            /* RSA key exchange is disallowed after 2023
             * https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-131Ar2.pdf */
            EXPECT_NOT_EQUAL(cipher_suite->key_exchange_alg, &s2n_rsa);

            /* AES is required.
             * Multiple s2n_ciphers represent AES, so just check the name.
             */
            EXPECT_NOT_NULL(strstr(cipher_suite->name, "AES"));

            /* Must use valid prf hash algorithm */
            bool hash_is_valid = false;
            s2n_hash_algorithm hash_alg = 0;
            EXPECT_SUCCESS(s2n_hmac_hash_alg(cipher_suite->prf_alg, &hash_alg));
            EXPECT_OK(s2n_fips_validate_hash_algorithm(hash_alg, &hash_is_valid));
            EXPECT_TRUE(hash_is_valid);
        }
    };

    /* Test s2n_fips_validate_signature_scheme */
    {
        /* Safety */
        {
            bool is_valid = false;
            EXPECT_ERROR_WITH_ERRNO(
                    s2n_fips_validate_signature_scheme(NULL, &is_valid),
                    S2N_ERR_NULL);
            EXPECT_ERROR_WITH_ERRNO(
                    s2n_fips_validate_signature_scheme(&s2n_null_sig_scheme, NULL),
                    S2N_ERR_NULL);
        }

        /* Test: Valid */
        const struct s2n_signature_scheme *valid[] = {
            &s2n_ecdsa_sha256,
            &s2n_rsa_pkcs1_sha384,
            &s2n_rsa_pss_pss_sha256,
        };
        for (size_t i = 0; i < s2n_array_len(valid); i++) {
            bool is_valid = false;
            EXPECT_OK(s2n_fips_validate_signature_scheme(valid[i], &is_valid));
            EXPECT_TRUE(is_valid);
        }

        /* Test: Invalid */
        const struct s2n_signature_scheme *invalid[] = {
            &s2n_rsa_pkcs1_md5_sha1,
            &s2n_rsa_pkcs1_sha1,
            &s2n_ecdsa_sha1,
            &s2n_null_sig_scheme,
        };
        for (size_t i = 0; i < s2n_array_len(invalid); i++) {
            bool is_valid = true;
            EXPECT_OK(s2n_fips_validate_signature_scheme(invalid[i], &is_valid));
            EXPECT_FALSE(is_valid);
        }

        /* Test: check all */
        const struct s2n_signature_preferences *all_sig_schemes =
                security_policy_test_all.signature_preferences;
        for (size_t i = 0; i < all_sig_schemes->count; i++) {
            const struct s2n_signature_scheme *sig_scheme = all_sig_schemes->signature_schemes[i];

            bool is_valid = false;
            EXPECT_OK(s2n_fips_validate_signature_scheme(sig_scheme, &is_valid));
            if (!is_valid) {
                continue;
            }

            /* Must be in the "test_all_fips" security policy */
            const struct s2n_signature_preferences *test_all_fips_prefs =
                    security_policy_test_all_fips.signature_preferences;
            bool is_in_test_all_fips_prefs = false;
            for (size_t j = 0; j < test_all_fips_prefs->count; j++) {
                if (sig_scheme == test_all_fips_prefs->signature_schemes[j]) {
                    is_in_test_all_fips_prefs = true;
                }
            }
            EXPECT_TRUE(is_in_test_all_fips_prefs);
        }
    };

    /* Test s2n_fips_validate_curve */
    {
        /* Safety */
        {
            bool is_valid = false;
            EXPECT_ERROR_WITH_ERRNO(
                    s2n_fips_validate_curve(NULL, &is_valid),
                    S2N_ERR_NULL);
            EXPECT_ERROR_WITH_ERRNO(
                    s2n_fips_validate_curve(&s2n_ecc_curve_secp256r1, NULL),
                    S2N_ERR_NULL);
        }

        /* Test: Valid */
        const struct s2n_ecc_named_curve *valid[] = { &s2n_ecc_curve_secp256r1 };
        for (size_t i = 0; i < s2n_array_len(valid); i++) {
            bool is_valid = false;
            EXPECT_OK(s2n_fips_validate_curve(valid[i], &is_valid));
            EXPECT_TRUE(is_valid);
        }

        /* Test: Invalid */
        const struct s2n_ecc_named_curve *invalid[] = { &s2n_ecc_curve_x25519 };
        for (size_t i = 0; i < s2n_array_len(invalid); i++) {
            bool is_valid = true;
            EXPECT_OK(s2n_fips_validate_curve(invalid[i], &is_valid));
            EXPECT_FALSE(is_valid);
        }

        /* Test: check all */
        for (size_t i = 0; i < s2n_ecc_preferences_test_all.count; i++) {
            const struct s2n_ecc_named_curve *curve = s2n_ecc_preferences_test_all.ecc_curves[i];

            bool is_valid = false;
            EXPECT_OK(s2n_fips_validate_curve(curve, &is_valid));
            if (!is_valid) {
                continue;
            }

            /* Must be in the "test_all_fips" security policy */
            const struct s2n_ecc_preferences *test_all_fips_prefs =
                    security_policy_test_all_fips.ecc_preferences;
            bool is_in_test_all_fips_prefs = false;
            for (size_t j = 0; j < test_all_fips_prefs->count; j++) {
                if (curve == test_all_fips_prefs->ecc_curves[j]) {
                    is_in_test_all_fips_prefs = true;
                }
            }
            EXPECT_TRUE(is_in_test_all_fips_prefs);
        }
    };

    /* Test s2n_fips_validate_version */
    {
        /* Safety */
        EXPECT_ERROR_WITH_ERRNO(s2n_fips_validate_version(0, NULL), S2N_ERR_NULL);

        /* Test: Valid */
        uint8_t valid[] = { S2N_TLS12, S2N_TLS13 };
        for (size_t i = 0; i < s2n_array_len(valid); i++) {
            bool is_valid = false;
            EXPECT_OK(s2n_fips_validate_version(valid[i], &is_valid));
            EXPECT_TRUE(is_valid);
        }

        /* Test: Invalid */
        uint8_t invalid[] = { 0, 1, S2N_SSLv2, S2N_SSLv3, S2N_TLS11 };
        for (size_t i = 0; i < s2n_array_len(invalid); i++) {
            bool is_valid = true;
            EXPECT_OK(s2n_fips_validate_version(invalid[i], &is_valid));
            EXPECT_FALSE(is_valid);
        }

        /* Test: check all */
        for (size_t version = 0; version < UINT8_MAX; version++) {
            bool is_valid = false;
            EXPECT_OK(s2n_fips_validate_version(version, &is_valid));
        }
    };

    END_TEST();
}
