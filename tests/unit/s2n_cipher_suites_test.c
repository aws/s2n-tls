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

/* This test checks that the compiler correctly implements deferred cleanup */
int main()
{
    BEGIN_TEST();

    /* Test: s2n_cipher_suite_from_wire */
    {
        /* Test: all cipher suites in s2n_all_cipher_suites are in IANA order
         * (Required for s2n_cipher_suite_from_wire to perform a search) */
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

        /* Test: all possible cipher suites are supported */
        {
            const struct s2n_security_policy *security_policy = NULL;
            const struct s2n_cipher_preferences *cipher_preferences = NULL;
            for (size_t i = 0; security_policy_selection[i].version != NULL; i++) {
                security_policy = security_policy_selection[i].security_policy;
                cipher_preferences = security_policy->cipher_preferences;
                for (size_t j = 0; j < cipher_preferences->count; j++) {
                    struct s2n_cipher_suite *cipher_suite = s2n_cipher_suite_from_wire(cipher_preferences->suites[j]->iana_value);

                    if (cipher_preferences->suites[j] == &s2n_null_cipher_suite) {
                        EXPECT_NULL(cipher_suite);
                        continue;
                    }

                    EXPECT_NOT_NULL(cipher_suite);
                    EXPECT_EQUAL(cipher_suite, cipher_preferences->suites[j]);
                }
            }
        }

        /* Test: S2N_CIPHER_SUITE_COUNT matches the number of supported cipher suites */
        {
            uint8_t wire[2] = { 0 };
            size_t actual_cipher_suite_count = 0;
            for (int i = 0; i < 0xffff; i++) {
                wire[0] = (i >> 8);
                wire[1] = i & 0xff;

                struct s2n_cipher_suite *s = s2n_cipher_suite_from_wire(wire);
                if (s != NULL) {
                    actual_cipher_suite_count++;
                }
            }
            EXPECT_EQUAL(cipher_preferences_test_all.count, S2N_CIPHER_SUITE_COUNT);
            EXPECT_EQUAL(actual_cipher_suite_count, S2N_CIPHER_SUITE_COUNT);
        }
    }

    END_TEST();
}
