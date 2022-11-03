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

#include "tls/s2n_cipher_suites.h"

int main()
{
    BEGIN_TEST();

    /* Test: s2n_all_cipher_suites */
    {
        /* Test: S2N_CIPHER_SUITE_COUNT matches the number of cipher suites in s2n_all_cipher_suites */
        {
            EXPECT_EQUAL(cipher_preferences_test_all.count, S2N_CIPHER_SUITE_COUNT);
        }

        /* Test: all cipher suites in s2n_all_cipher_suites are in IANA order */
        {
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));

            const uint8_t cipher_suite_count = cipher_preferences_test_all.count;
            for (size_t i = 0; i < cipher_suite_count - 1; i++) {
                int cipher_suite_order = memcmp(cipher_preferences_test_all.suites[i]->iana_value,
                        cipher_preferences_test_all.suites[i + 1]->iana_value, 2);
                EXPECT_TRUE(cipher_suite_order < 0);
            }
            EXPECT_SUCCESS(s2n_connection_free(conn));
        }

        /* Test: all possible cipher suites are in s2n_all_cipher_suites */
        {
            const struct s2n_security_policy *security_policy = NULL;
            const struct s2n_cipher_preferences *cipher_preferences = NULL;
            for (size_t policy_index = 0; security_policy_selection[policy_index].version != NULL; policy_index++) {
                security_policy = security_policy_selection[policy_index].security_policy;
                cipher_preferences = security_policy->cipher_preferences;
                for (size_t cipher_index = 0; cipher_index < cipher_preferences->count; cipher_index++) {
                    /* The null cipher suite is just a placeholder, and is not included */
                    if (cipher_preferences->suites[cipher_index] == &s2n_null_cipher_suite) {
                        continue;
                    }

                    const struct s2n_cipher_suite *match = NULL;
                    for (size_t all_index = 0; all_index < cipher_preferences_test_all.count; all_index++) {
                        if (0 == memcmp(cipher_preferences->suites[cipher_index]->iana_value,
                                        cipher_preferences_test_all.suites[all_index]->iana_value,
                                        S2N_TLS_CIPHER_SUITE_LEN)) {
                            EXPECT_NULL(match);
                            match = cipher_preferences_test_all.suites[all_index];
                        }
                    }
                    EXPECT_NOT_NULL(match);
                    EXPECT_EQUAL(match, cipher_preferences->suites[cipher_index]);
                }
            }
        }
    }

    /* Test s2n_cipher_suite_from_iana */
    {
        /* Safety */
        {
            uint8_t iana[S2N_TLS_CIPHER_SUITE_LEN] = { 0 };
            struct s2n_cipher_suite *cipher_suite = NULL;
            EXPECT_ERROR_WITH_ERRNO(s2n_cipher_suite_from_iana(NULL, sizeof(iana), &cipher_suite), S2N_ERR_NULL);
            EXPECT_ERROR_WITH_ERRNO(s2n_cipher_suite_from_iana(iana, sizeof(iana), NULL), S2N_ERR_NULL);
            EXPECT_ERROR_WITH_ERRNO(s2n_cipher_suite_from_iana(iana, sizeof(iana) - 1, &cipher_suite), S2N_ERR_SAFETY);
            EXPECT_ERROR_WITH_ERRNO(s2n_cipher_suite_from_iana(iana, sizeof(iana) + 1, &cipher_suite), S2N_ERR_SAFETY);
        }

        /* Known values */
        {
            uint8_t null_iana[S2N_TLS_CIPHER_SUITE_LEN] = { 0 };
            struct s2n_cipher_suite *cipher_suite = &s2n_tls13_aes_256_gcm_sha384;
            EXPECT_ERROR_WITH_ERRNO(s2n_cipher_suite_from_iana(null_iana, sizeof(null_iana), &cipher_suite),
                    S2N_ERR_CIPHER_NOT_SUPPORTED);
            EXPECT_EQUAL(cipher_suite, NULL);

            uint8_t tls12_iana[] = { TLS_RSA_WITH_AES_128_CBC_SHA };
            cipher_suite = NULL;
            EXPECT_OK(s2n_cipher_suite_from_iana(tls12_iana, sizeof(tls12_iana), &cipher_suite));
            EXPECT_EQUAL(cipher_suite, &s2n_rsa_with_aes_128_cbc_sha);

            cipher_suite = NULL;
            EXPECT_OK(s2n_cipher_suite_from_iana(s2n_tls13_aes_256_gcm_sha384.iana_value,
                    sizeof(s2n_tls13_aes_256_gcm_sha384.iana_value), &cipher_suite));
            EXPECT_EQUAL(cipher_suite, &s2n_tls13_aes_256_gcm_sha384);
        }

        /* Conversion is correct for all supported cipher suites */
        {
            struct s2n_cipher_suite *actual_cipher_suite = NULL;
            struct s2n_cipher_suite *expected_cipher_suite = NULL;
            for (size_t i = 0; i < cipher_preferences_test_all.count; i++) {
                expected_cipher_suite = cipher_preferences_test_all.suites[i];
                actual_cipher_suite = NULL;

                EXPECT_OK(s2n_cipher_suite_from_iana(expected_cipher_suite->iana_value,
                        sizeof(expected_cipher_suite->iana_value), &actual_cipher_suite));
                EXPECT_EQUAL(expected_cipher_suite, actual_cipher_suite);
            }
        }

        /* Conversion is correct for all possible iana values */
        {
            size_t supported_i = 0;
            struct s2n_cipher_suite *actual_cipher_suite = NULL;
            uint8_t iana_value[S2N_TLS_CIPHER_SUITE_LEN] = { 0 };
            for(size_t i0 = 0; i0 <= UINT8_MAX; i0++) {
                iana_value[0] = i0;
                for (size_t i1 = 0; i1 <= UINT8_MAX; i1++) {
                    iana_value[1] = i1;

                    s2n_result r = s2n_cipher_suite_from_iana(iana_value, sizeof(iana_value), &actual_cipher_suite);

                    bool is_supported = supported_i < cipher_preferences_test_all.count
                            && memcmp(iana_value, cipher_preferences_test_all.suites[supported_i]->iana_value, S2N_TLS_CIPHER_SUITE_LEN) == 0;
                    if (is_supported) {
                        EXPECT_OK(r);
                        EXPECT_EQUAL(actual_cipher_suite, cipher_preferences_test_all.suites[supported_i]);
                        supported_i++;
                    } else {
                        EXPECT_ERROR_WITH_ERRNO(r, S2N_ERR_CIPHER_NOT_SUPPORTED);
                        EXPECT_NULL(actual_cipher_suite);
                    }

                }
            }
            EXPECT_EQUAL(supported_i, cipher_preferences_test_all.count);
        }
    }

    END_TEST();
}
