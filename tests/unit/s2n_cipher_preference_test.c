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

int main(int argc, char **argv)
{
    BEGIN_TEST();

    const struct s2n_cipher_preferences *preferences = NULL;

    /* Test common known good cipher suites for expected configuration */
    {
        EXPECT_SUCCESS(s2n_find_cipher_pref_from_version("default", &preferences));
        EXPECT_TRUE(s2n_ecc_extension_required(preferences));
        EXPECT_FALSE(s2n_pq_kem_extension_required(preferences));
        EXPECT_EQUAL(0, preferences->kem_count);
        EXPECT_FALSE(s2n_cipher_preference_supports_tls13(preferences));
        EXPECT_NULL(preferences->kems);

        preferences = NULL;
        EXPECT_SUCCESS(s2n_find_cipher_pref_from_version("default_tls13", &preferences));
        EXPECT_TRUE(s2n_ecc_extension_required(preferences));
        EXPECT_FALSE(s2n_pq_kem_extension_required(preferences));
        EXPECT_TRUE(s2n_cipher_preference_supports_tls13(preferences));
        EXPECT_EQUAL(0, preferences->kem_count);
        EXPECT_NULL(preferences->kems);

        preferences = NULL;
        EXPECT_SUCCESS(s2n_find_cipher_pref_from_version("test_all", &preferences));
        EXPECT_TRUE(s2n_ecc_extension_required(preferences));
        EXPECT_TRUE(s2n_cipher_preference_supports_tls13(preferences));
#if !defined(S2N_NO_PQ)
        EXPECT_EQUAL(4, preferences->kem_count);
        EXPECT_TRUE(s2n_pq_kem_extension_required(preferences));
        EXPECT_NOT_NULL(preferences->kems);
        EXPECT_EQUAL(preferences->kems, pq_kems_r2r1);
#else
        EXPECT_EQUAL(0, preferences->kem_count);
        EXPECT_NULL(preferences->kems);
#endif

        preferences = NULL;
        EXPECT_SUCCESS(s2n_find_cipher_pref_from_version("KMS-TLS-1-0-2018-10", &preferences));
        EXPECT_TRUE(s2n_ecc_extension_required(preferences));
        EXPECT_FALSE(s2n_pq_kem_extension_required(preferences));
        EXPECT_FALSE(s2n_cipher_preference_supports_tls13(preferences));
        EXPECT_EQUAL(0, preferences->kem_count);
        EXPECT_NULL(preferences->kems);

#if !defined(S2N_NO_PQ)
        preferences = NULL;
        EXPECT_SUCCESS(s2n_find_cipher_pref_from_version("KMS-PQ-TLS-1-0-2019-06", &preferences));
        EXPECT_TRUE(s2n_ecc_extension_required(preferences));
        EXPECT_TRUE(s2n_pq_kem_extension_required(preferences));
        EXPECT_FALSE(s2n_cipher_preference_supports_tls13(preferences));
        EXPECT_EQUAL(2, preferences->kem_count);
        EXPECT_NOT_NULL(preferences->kems);
        EXPECT_EQUAL(preferences->kems, pq_kems_r1);

        preferences = NULL;
        EXPECT_SUCCESS(s2n_find_cipher_pref_from_version("PQ-SIKE-TEST-TLS-1-0-2019-11", &preferences));
        EXPECT_TRUE(s2n_ecc_extension_required(preferences));
        EXPECT_TRUE(s2n_pq_kem_extension_required(preferences));
        EXPECT_FALSE(s2n_cipher_preference_supports_tls13(preferences));
        EXPECT_EQUAL(1, preferences->kem_count);
        EXPECT_NOT_NULL(preferences->kems);
        EXPECT_EQUAL(preferences->kems, pq_kems_sike_r1);

        preferences = NULL;
        EXPECT_SUCCESS(s2n_find_cipher_pref_from_version("PQ-SIKE-TEST-TLS-1-0-2020-02", &preferences));
        EXPECT_TRUE(s2n_ecc_extension_required(preferences));
        EXPECT_TRUE(s2n_pq_kem_extension_required(preferences));
        EXPECT_FALSE(s2n_cipher_preference_supports_tls13(preferences));
        EXPECT_EQUAL(2, preferences->kem_count);
        EXPECT_NOT_NULL(preferences->kems);
        EXPECT_EQUAL(preferences->kems, pq_kems_sike_r2r1);

        preferences = NULL;
        EXPECT_SUCCESS(s2n_find_cipher_pref_from_version("KMS-PQ-TLS-1-0-2020-02", &preferences));
        EXPECT_TRUE(s2n_ecc_extension_required(preferences));
        EXPECT_TRUE(s2n_pq_kem_extension_required(preferences));
        EXPECT_FALSE(s2n_cipher_preference_supports_tls13(preferences));
        EXPECT_EQUAL(4, preferences->kem_count);
        EXPECT_NOT_NULL(preferences->kems);
        EXPECT_EQUAL(preferences->kems, pq_kems_r2r1);
#else
        preferences = NULL;
        EXPECT_FAILURE(s2n_find_cipher_pref_from_version("KMS-PQ-TLS-1-0-2019-06", &preferences));
        EXPECT_EQUAL(preferences, NULL);

        EXPECT_FAILURE(s2n_find_cipher_pref_from_version("PQ-SIKE-TEST-TLS-1-0-2019-11", &preferences));
        EXPECT_EQUAL(preferences, NULL);

        EXPECT_FAILURE(s2n_find_cipher_pref_from_version("PQ-SIKE-TEST-TLS-1-0-2020-02", &preferences));
        EXPECT_EQUAL(preferences, NULL);

        EXPECT_FAILURE(s2n_find_cipher_pref_from_version("KMS-PQ-TLS-1-0-2020-02", &preferences));
        EXPECT_EQUAL(preferences, NULL);
#endif

        preferences = NULL;
        EXPECT_SUCCESS(s2n_find_cipher_pref_from_version("20141001", &preferences));
        EXPECT_FALSE(s2n_ecc_extension_required(preferences));
        EXPECT_FALSE(s2n_pq_kem_extension_required(preferences));
        EXPECT_EQUAL(0, preferences->kem_count);
        EXPECT_NULL(preferences->kems);
    }

    /* Test s2n_cipher_preference_supports_tls13() with all cipher preferences */
    {
        char tls12_only_cipher_preference_strings[][255] = {
            "default",
            "default_fips",
            "ELBSecurityPolicy-TLS-1-0-2015-04",
            "ELBSecurityPolicy-TLS-1-0-2015-05",
            "ELBSecurityPolicy-2016-08",
            "ELBSecurityPolicy-TLS-1-1-2017-01",
            "ELBSecurityPolicy-TLS-1-2-2017-01",
            "ELBSecurityPolicy-TLS-1-2-Ext-2018-06",
            "ELBSecurityPolicy-FS-2018-06",
            "ELBSecurityPolicy-FS-1-2-2019-08",
            "ELBSecurityPolicy-FS-1-1-2019-08",
            "ELBSecurityPolicy-FS-1-2-Res-2019-08",
            "CloudFront-Upstream",
            "CloudFront-Upstream-TLS-1-0",
            "CloudFront-Upstream-TLS-1-1",
            "CloudFront-Upstream-TLS-1-2",
            "CloudFront-SSL-v-3",
            "CloudFront-TLS-1-0-2014",
            "CloudFront-TLS-1-0-2016",
            "CloudFront-TLS-1-1-2016",
            "CloudFront-TLS-1-2-2018",
            "CloudFront-TLS-1-2-2019",
            "CloudFront-TLS-1-2-2020",
            "KMS-TLS-1-0-2018-10",
#if !defined(S2N_NO_PQ)
            "KMS-PQ-TLS-1-0-2019-06",
            "KMS-PQ-TLS-1-0-2020-02",
            "PQ-SIKE-TEST-TLS-1-0-2019-11",
            "PQ-SIKE-TEST-TLS-1-0-2020-02",
#endif
            "KMS-FIPS-TLS-1-2-2018-10",
            "20140601",
            "20141001",
            "20150202",
            "20150214",
            "20150306",
            "20160411",
            "20160804",
            "20160824",
            "20170210",
            "20170328",
            "20190214",
            "20170405",
            "20170718",
            "20190120",
            "20190121",
            "20190122",
            "test_all_fips",
            "test_all_ecdsa",
            "test_ecdsa_priority",
            "test_all_tls12",
        };

        for (size_t i = 0; i < s2n_array_len(tls12_only_cipher_preference_strings); i++) {
            preferences = NULL;
            EXPECT_SUCCESS(s2n_find_cipher_pref_from_version(tls12_only_cipher_preference_strings[i], &preferences));
            EXPECT_FALSE(s2n_cipher_preference_supports_tls13(preferences));
        }

        char tls13_cipher_preference_strings[][255] = {
            "default_tls13",
            "test_all",
            "test_all_tls13",
        };
        for (size_t i = 0; i < s2n_array_len(tls13_cipher_preference_strings); i++) {
            preferences = NULL;
            EXPECT_SUCCESS(s2n_find_cipher_pref_from_version(tls13_cipher_preference_strings[i], &preferences));
            EXPECT_TRUE(s2n_cipher_preference_supports_tls13(preferences));
        }
    }

    /* Test that null fails */
    {
        preferences = NULL;
        EXPECT_FAILURE(s2n_ecc_extension_required(preferences));
        EXPECT_FAILURE(s2n_pq_kem_extension_required(preferences));
        EXPECT_FALSE(s2n_cipher_preference_supports_tls13(preferences));
    }

    /* Test that anything not automatically configured in s2n_cipher_preferences_init fails */
    {
        struct s2n_cipher_suite *fake_suites[] = {
                &s2n_ecdhe_bike_rsa_with_aes_256_gcm_sha384,
        };
        const struct s2n_cipher_preferences fake_preferences = {
                .count = 1,
                .suites = fake_suites,
                .minimum_protocol_version = S2N_TLS10,
        };
        preferences = &fake_preferences;
        EXPECT_FAILURE(s2n_ecc_extension_required(preferences));
        EXPECT_FAILURE(s2n_pq_kem_extension_required(preferences));
        EXPECT_FALSE(s2n_cipher_preference_supports_tls13(preferences));
    }

    END_TEST();
}
