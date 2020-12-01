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

#if !defined(S2N_NO_PQ)
#define NUM_PQ_CIPHER_SUITES 3
const struct s2n_cipher_suite *pq_cipher_suites[NUM_PQ_CIPHER_SUITES] = {
        &s2n_ecdhe_bike_rsa_with_aes_256_gcm_sha384,    /* 0xFF,0x04 */
        &s2n_ecdhe_sike_rsa_with_aes_256_gcm_sha384,    /* 0xFF,0x08 */
        &s2n_ecdhe_kyber_rsa_with_aes_256_gcm_sha384,   /* 0xFF,0x0C */
};
#else
#define NUM_PQ_CIPHER_SUITES 0
#endif

int main() {
    BEGIN_TEST();

    {
        EXPECT_EQUAL(cipher_preferences_test_all_no_pq.count + NUM_PQ_CIPHER_SUITES, cipher_preferences_test_all.count);

        /* Assert that cipher_preferences_test_all_no_pq is a PQ-less sublist of cipher_preferences_test_all */
        size_t i;
        for (i = 0; i < cipher_preferences_test_all_no_pq.count; i++) {
            EXPECT_EQUAL(cipher_preferences_test_all_no_pq.suites[i], cipher_preferences_test_all.suites[i]);
            EXPECT_FALSE(s2n_kex_includes(cipher_preferences_test_all_no_pq.suites[i]->key_exchange_alg, &s2n_kem));

            if (i > 0) {
                /* Ciphers should be in order by IANA value */
                int iana_compare = memcmp(cipher_preferences_test_all_no_pq.suites[i-1]->iana_value,
                        cipher_preferences_test_all_no_pq.suites[i]->iana_value, 2);
                EXPECT_TRUE(iana_compare < 0);
            }
        }

#if !defined(S2N_NO_PQ)
        /* The leftover suites on cipher_preferences_test_all should be PQ */
        for (size_t j = 0; j < NUM_PQ_CIPHER_SUITES; j++) {
            EXPECT_EQUAL(cipher_preferences_test_all.suites[i+j], pq_cipher_suites[j]);
            EXPECT_TRUE(s2n_kex_includes(cipher_preferences_test_all.suites[i+j]->key_exchange_alg, &s2n_kem));
        }
#endif
    }

    {
        EXPECT_EQUAL(cipher_preferences_test_all_tls12_no_pq.count + NUM_PQ_CIPHER_SUITES, cipher_preferences_test_all_tls12.count);

        /* Assert that cipher_preferences_test_all_tls12_no_pq is a PQ-less sublist of cipher_preferences_test_all_tls12 */
        size_t i;
        for (i = 0; i < cipher_preferences_test_all_tls12_no_pq.count; i++) {
            EXPECT_EQUAL(cipher_preferences_test_all_tls12_no_pq.suites[i], cipher_preferences_test_all_tls12.suites[i]);
            EXPECT_FALSE(s2n_kex_includes(cipher_preferences_test_all_tls12_no_pq.suites[i]->key_exchange_alg, &s2n_kem));

            if (i > 0) {
                /* Ciphers should be in order by IANA value */
                int iana_compare = memcmp(cipher_preferences_test_all_tls12_no_pq.suites[i-1]->iana_value,
                        cipher_preferences_test_all_tls12_no_pq.suites[i]->iana_value, 2);
                EXPECT_TRUE(iana_compare < 0);
            }
        }

#if !defined(S2N_NO_PQ)
        /* The leftover suites on cipher_preferences_test_all_tls12 should be PQ */
        for (size_t j = 0; j < NUM_PQ_CIPHER_SUITES; j++) {
            EXPECT_EQUAL(cipher_preferences_test_all_tls12.suites[i+j], pq_cipher_suites[j]);
            EXPECT_TRUE(s2n_kex_includes(cipher_preferences_test_all_tls12.suites[i+j]->key_exchange_alg, &s2n_kem));
        }
#endif
    }

    END_TEST();
}
