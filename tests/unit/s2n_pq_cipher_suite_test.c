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
#include "tls/s2n_cipher_preferences.h"
#include "tls/s2n_kex.h"

/* s2n_ecdhe_kyber_rsa_with_aes_256_gcm_sha384,
 * s2n_ecdhe_bike_rsa_with_aes_256_gcm_sha384,
 * s2n_ecdhe_sike_rsa_with_aes_256_gcm_sha384 */
#define NUM_PQ_CIPHER_SUITES 3

int main() {
    BEGIN_TEST();

    /* Assert that cipher_preferences_test_all_no_pq is equal to
     * cipher_preferences_test_all without the PQ ciphers */
    {
        EXPECT_EQUAL(cipher_preferences_test_all_no_pq.count + NUM_PQ_CIPHER_SUITES, cipher_preferences_test_all.count);

        size_t num_found_pq_cipher_suites = 0;
        for (size_t i = 0; i < cipher_preferences_test_all.count; i++) {
            if (i < cipher_preferences_test_all_no_pq.count) {
                /* Since the PQ ciphers are at the end of the test_all list, the two
                 * lists should be identical up to that point. */
                EXPECT_EQUAL(cipher_preferences_test_all.suites[i], cipher_preferences_test_all_no_pq.suites[i]);
                EXPECT_FALSE(s2n_kex_includes(cipher_preferences_test_all.suites[i]->key_exchange_alg, &s2n_kem));
            } else {
                /* Any cipher on test_all that is not on test_all_no_pq should be a PQ cipher. */
                EXPECT_TRUE(s2n_kex_includes(cipher_preferences_test_all.suites[i]->key_exchange_alg, &s2n_kem));
                num_found_pq_cipher_suites++;
            }
        }

        EXPECT_EQUAL(num_found_pq_cipher_suites, NUM_PQ_CIPHER_SUITES);
    }

    /* Assert that cipher_preferences_test_all_tls12_no_pq is equal to cipher_preferences_test_all_tls12
     * without the PQ ciphers */
    {
        EXPECT_EQUAL(cipher_preferences_test_all_tls12_no_pq.count + NUM_PQ_CIPHER_SUITES, cipher_preferences_test_all_tls12.count);

        size_t num_found_pq_cipher_suites = 0;
        for (size_t i = 0; i < cipher_preferences_test_all_tls12.count; i++) {
            if (i < cipher_preferences_test_all_tls12_no_pq.count) {
                /* Since the PQ ciphers are at the end of the test_all_tls12 list, the two
                 * lists should be identical up to that point. */
                EXPECT_EQUAL(cipher_preferences_test_all_tls12.suites[i], cipher_preferences_test_all_tls12_no_pq.suites[i]);
                EXPECT_FALSE(s2n_kex_includes(cipher_preferences_test_all_tls12.suites[i]->key_exchange_alg, &s2n_kem));
            } else {
                /* Any cipher on test_all that is not on test_all_no_pq should be a PQ cipher. */
                EXPECT_TRUE(s2n_kex_includes(cipher_preferences_test_all_tls12.suites[i]->key_exchange_alg, &s2n_kem));
                num_found_pq_cipher_suites++;
            }
        }

        EXPECT_EQUAL(num_found_pq_cipher_suites, NUM_PQ_CIPHER_SUITES);
    }

    END_TEST();
    return 0;
}
