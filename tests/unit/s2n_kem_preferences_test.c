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

#include "tls/s2n_kem_preferences.h"

#include "crypto/s2n_fips.h"
#include "s2n_test.h"
#include "tls/s2n_tls_parameters.h"

int main(int argc, char **argv)
{
    BEGIN_TEST();
    EXPECT_SUCCESS(s2n_disable_tls13_in_test());

    EXPECT_FALSE(s2n_kem_preferences_includes_tls13_kem_group(&kem_preferences_null, TLS_PQ_KEM_GROUP_ID_X25519_KYBER_512_R3));
    EXPECT_FALSE(s2n_kem_preferences_includes_tls13_kem_group(&kem_preferences_null, TLS_PQ_KEM_GROUP_ID_SECP256R1_KYBER_512_R3));
    EXPECT_FALSE(s2n_kem_preferences_includes_tls13_kem_group(&kem_preferences_null, TLS_PQ_KEM_GROUP_ID_SECP384R1_KYBER_768_R3));
    EXPECT_FALSE(s2n_kem_preferences_includes_tls13_kem_group(&kem_preferences_null, TLS_PQ_KEM_GROUP_ID_SECP521R1_KYBER_1024_R3));

    {
        const struct s2n_kem_group *test_kem_groups[] = {
            &s2n_secp256r1_kyber_512_r3,
#if EVP_APIS_SUPPORTED
            &s2n_x25519_kyber_512_r3,
#endif
#if defined(S2N_LIBCRYPTO_SUPPORTS_KYBER)
            &s2n_secp384r1_kyber_768_r3,
            &s2n_secp521r1_kyber_1024_r3,
#endif
        };

        const struct s2n_kem_preferences test_prefs = {
            .kem_count = 0,
            .kems = NULL,
            .tls13_kem_group_count = s2n_array_len(test_kem_groups),
            .tls13_kem_groups = test_kem_groups,
        };

        EXPECT_TRUE(s2n_kem_preferences_includes_tls13_kem_group(&test_prefs, TLS_PQ_KEM_GROUP_ID_SECP256R1_KYBER_512_R3));

#if EVP_APIS_SUPPORTED
        EXPECT_TRUE(s2n_kem_preferences_includes_tls13_kem_group(&test_prefs, TLS_PQ_KEM_GROUP_ID_X25519_KYBER_512_R3));
#else
        EXPECT_FALSE(s2n_kem_preferences_includes_tls13_kem_group(&test_prefs, TLS_PQ_KEM_GROUP_ID_X25519_KYBER_512_R3));
#endif

#if defined(S2N_LIBCRYPTO_SUPPORTS_KYBER)
        EXPECT_TRUE(s2n_kem_preferences_includes_tls13_kem_group(&test_prefs, TLS_PQ_KEM_GROUP_ID_SECP384R1_KYBER_768_R3));
        EXPECT_TRUE(s2n_kem_preferences_includes_tls13_kem_group(&test_prefs, TLS_PQ_KEM_GROUP_ID_SECP521R1_KYBER_1024_R3));
#else
        EXPECT_FALSE(s2n_kem_preferences_includes_tls13_kem_group(&test_prefs, TLS_PQ_KEM_GROUP_ID_SECP384R1_KYBER_768_R3));
        EXPECT_FALSE(s2n_kem_preferences_includes_tls13_kem_group(&test_prefs, TLS_PQ_KEM_GROUP_ID_SECP521R1_KYBER_1024_R3));
#endif
    };

    END_TEST();
}
