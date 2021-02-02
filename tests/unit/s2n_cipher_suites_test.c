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

            int cipher_suite_order;
            const uint8_t cipher_suite_count = cipher_preferences_test_all.count;
            for (size_t i = 0; i < cipher_suite_count - 1; i++) {
                cipher_suite_order = memcmp(cipher_preferences_test_all.suites[i]->iana_value,
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
                            match = cipher_preferences_test_all.suites[all_index];
                        }
                    }
                    EXPECT_NOT_NULL(match);
                    EXPECT_EQUAL(match, cipher_preferences->suites[cipher_index]);
                }
            }
        }
    }

    END_TEST();
}
