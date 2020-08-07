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
#include "tls/s2n_kem_preferences.h"
#include "tls/s2n_tls_parameters.h"
#include "crypto/s2n_fips.h"

int main(int argc, char **argv)
{
    BEGIN_TEST();

    EXPECT_FALSE(s2n_kem_preferences_includes_tls13_kem_group(NULL, TLS_PQ_KEM_GROUP_ID_SECP256R1_SIKE_P434_R2));
    EXPECT_FALSE(s2n_kem_preferences_includes_tls13_kem_group(&kem_preferences_null, TLS_PQ_KEM_GROUP_ID_X25519_SIKE_P434_R2));
    EXPECT_FALSE(s2n_kem_preferences_includes_tls13_kem_group(&kem_preferences_null, TLS_PQ_KEM_GROUP_ID_SECP256R1_SIKE_P434_R2));
    EXPECT_FALSE(s2n_kem_preferences_includes_tls13_kem_group(&kem_preferences_null, TLS_PQ_KEM_GROUP_ID_X25519_BIKE1_L1_R2));
    EXPECT_FALSE(s2n_kem_preferences_includes_tls13_kem_group(&kem_preferences_null, TLS_PQ_KEM_GROUP_ID_SECP256R1_BIKE1_L1_R2));

#if !defined(S2N_NO_PQ)

    if (s2n_is_in_fips_mode()) {
        /* There is no support for PQ KEMs while in FIPS mode */
        END_TEST();
    }

    {
        EXPECT_FALSE(s2n_kem_preferences_includes_tls13_kem_group(&kem_preferences_kms_pq_tls_1_0_2019_06, TLS_PQ_KEM_GROUP_ID_X25519_SIKE_P434_R2));
        EXPECT_FALSE(s2n_kem_preferences_includes_tls13_kem_group(&kem_preferences_kms_pq_tls_1_0_2019_06, TLS_PQ_KEM_GROUP_ID_SECP256R1_SIKE_P434_R2));
        EXPECT_FALSE(s2n_kem_preferences_includes_tls13_kem_group(&kem_preferences_kms_pq_tls_1_0_2019_06, TLS_PQ_KEM_GROUP_ID_X25519_BIKE1_L1_R2));
        EXPECT_FALSE(s2n_kem_preferences_includes_tls13_kem_group(&kem_preferences_kms_pq_tls_1_0_2019_06, TLS_PQ_KEM_GROUP_ID_SECP256R1_BIKE1_L1_R2));

        EXPECT_FALSE(s2n_kem_preferences_includes_tls13_kem_group(&kem_preferences_kms_pq_tls_1_0_2020_02, TLS_PQ_KEM_GROUP_ID_X25519_SIKE_P434_R2));
        EXPECT_FALSE(s2n_kem_preferences_includes_tls13_kem_group(&kem_preferences_kms_pq_tls_1_0_2020_02, TLS_PQ_KEM_GROUP_ID_SECP256R1_SIKE_P434_R2));
        EXPECT_FALSE(s2n_kem_preferences_includes_tls13_kem_group(&kem_preferences_kms_pq_tls_1_0_2020_02, TLS_PQ_KEM_GROUP_ID_X25519_BIKE1_L1_R2));
        EXPECT_FALSE(s2n_kem_preferences_includes_tls13_kem_group(&kem_preferences_kms_pq_tls_1_0_2020_02, TLS_PQ_KEM_GROUP_ID_SECP256R1_BIKE1_L1_R2));

        EXPECT_FALSE(s2n_kem_preferences_includes_tls13_kem_group(&kem_preferences_kms_pq_tls_1_0_2020_07, TLS_PQ_KEM_GROUP_ID_X25519_SIKE_P434_R2));
        EXPECT_FALSE(s2n_kem_preferences_includes_tls13_kem_group(&kem_preferences_kms_pq_tls_1_0_2020_07, TLS_PQ_KEM_GROUP_ID_SECP256R1_SIKE_P434_R2));
        EXPECT_FALSE(s2n_kem_preferences_includes_tls13_kem_group(&kem_preferences_kms_pq_tls_1_0_2020_07, TLS_PQ_KEM_GROUP_ID_X25519_BIKE1_L1_R2));
        EXPECT_FALSE(s2n_kem_preferences_includes_tls13_kem_group(&kem_preferences_kms_pq_tls_1_0_2020_07, TLS_PQ_KEM_GROUP_ID_SECP256R1_BIKE1_L1_R2));

        EXPECT_FALSE(s2n_kem_preferences_includes_tls13_kem_group(&kem_preferences_pq_sike_test_tls_1_0_2019_11, TLS_PQ_KEM_GROUP_ID_X25519_SIKE_P434_R2));
        EXPECT_FALSE(s2n_kem_preferences_includes_tls13_kem_group(&kem_preferences_pq_sike_test_tls_1_0_2019_11, TLS_PQ_KEM_GROUP_ID_SECP256R1_SIKE_P434_R2));
        EXPECT_FALSE(s2n_kem_preferences_includes_tls13_kem_group(&kem_preferences_pq_sike_test_tls_1_0_2019_11, TLS_PQ_KEM_GROUP_ID_X25519_BIKE1_L1_R2));
        EXPECT_FALSE(s2n_kem_preferences_includes_tls13_kem_group(&kem_preferences_pq_sike_test_tls_1_0_2019_11, TLS_PQ_KEM_GROUP_ID_SECP256R1_BIKE1_L1_R2));

        EXPECT_FALSE(s2n_kem_preferences_includes_tls13_kem_group(&kem_preferences_pq_sike_test_tls_1_0_2020_02, TLS_PQ_KEM_GROUP_ID_X25519_SIKE_P434_R2));
        EXPECT_FALSE(s2n_kem_preferences_includes_tls13_kem_group(&kem_preferences_pq_sike_test_tls_1_0_2020_02, TLS_PQ_KEM_GROUP_ID_SECP256R1_SIKE_P434_R2));
        EXPECT_FALSE(s2n_kem_preferences_includes_tls13_kem_group(&kem_preferences_pq_sike_test_tls_1_0_2020_02, TLS_PQ_KEM_GROUP_ID_X25519_BIKE1_L1_R2));
        EXPECT_FALSE(s2n_kem_preferences_includes_tls13_kem_group(&kem_preferences_pq_sike_test_tls_1_0_2020_02, TLS_PQ_KEM_GROUP_ID_SECP256R1_BIKE1_L1_R2));
    }
    {
        const struct s2n_kem_group *test_kem_groups[] = {
                &s2n_secp256r1_sike_p434_r2,
                &s2n_secp256r1_bike1_l1_r2,
#if EVP_APIS_SUPPORTED
                &s2n_x25519_sike_p434_r2,
                &s2n_x25519_bike1_l1_r2,
#endif
        };

        const struct s2n_kem_preferences test_prefs = {
                .kem_count = 0,
                .kems = NULL,
                .tls13_kem_group_count = s2n_array_len(test_kem_groups),
                .tls13_kem_groups = test_kem_groups,
        };

        EXPECT_TRUE(s2n_kem_preferences_includes_tls13_kem_group(&test_prefs, TLS_PQ_KEM_GROUP_ID_SECP256R1_SIKE_P434_R2));
        EXPECT_TRUE(s2n_kem_preferences_includes_tls13_kem_group(&test_prefs, TLS_PQ_KEM_GROUP_ID_SECP256R1_BIKE1_L1_R2));
#if EVP_APIS_SUPPORTED
        EXPECT_TRUE(s2n_kem_preferences_includes_tls13_kem_group(&test_prefs, TLS_PQ_KEM_GROUP_ID_X25519_SIKE_P434_R2));
        EXPECT_TRUE(s2n_kem_preferences_includes_tls13_kem_group(&test_prefs, TLS_PQ_KEM_GROUP_ID_X25519_BIKE1_L1_R2));
#else
        EXPECT_FALSE(s2n_kem_preferences_includes_tls13_kem_group(&test_prefs, TLS_PQ_KEM_GROUP_ID_X25519_SIKE_P434_R2));
        EXPECT_FALSE(s2n_kem_preferences_includes_tls13_kem_group(&test_prefs, TLS_PQ_KEM_GROUP_ID_X25519_BIKE1_L1_R2));
#endif

    }


#endif

    END_TEST();
}
