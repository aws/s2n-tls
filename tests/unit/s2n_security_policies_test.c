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

#include "tls/s2n_security_policies.h"

int main(int argc, char **argv)
{
    BEGIN_TEST();

    const struct s2n_security_policy *security_policy = NULL;

    /* Test common known good cipher suites for expected configuration */
    {
        EXPECT_SUCCESS(s2n_find_security_policy_from_version("default", &security_policy));
        EXPECT_TRUE(s2n_ecc_is_extension_required(security_policy));
        EXPECT_FALSE(s2n_pq_kem_is_extension_required(security_policy));
        EXPECT_NULL(security_policy->kem_preferences->kems);
        EXPECT_EQUAL(0, security_policy->kem_preferences->count);
        EXPECT_FALSE(s2n_security_policy_supports_tls13(security_policy));

        security_policy = NULL;
        EXPECT_SUCCESS(s2n_find_security_policy_from_version("default_tls13", &security_policy));
        EXPECT_TRUE(s2n_ecc_is_extension_required(security_policy));
        EXPECT_FALSE(s2n_pq_kem_is_extension_required(security_policy));
        EXPECT_TRUE(s2n_security_policy_supports_tls13(security_policy));
        EXPECT_EQUAL(0, security_policy->kem_preferences->kems);
        EXPECT_NULL(security_policy->kem_preferences->kems);

        security_policy = NULL;
        EXPECT_SUCCESS(s2n_find_security_policy_from_version("test_all", &security_policy));
        EXPECT_TRUE(s2n_ecc_is_extension_required(security_policy));
#if !defined(S2N_NO_PQ)
        EXPECT_TRUE(s2n_pq_kem_is_extension_required(security_policy));
        EXPECT_EQUAL(4, security_policy->kem_preferences->count);
        EXPECT_NOT_NULL(security_policy->kem_preferences->kems);
        EXPECT_EQUAL(security_policy->kem_preferences->kems, pq_kems_r2r1);
#else
        EXPECT_FALSE(s2n_pq_kem_is_extension_required(security_policy));
        EXPECT_EQUAL(0, security_policy->kem_preferences->count);
        EXPECT_NULL(security_policy->kem_preferences->kems);
#endif

        security_policy = NULL;
        EXPECT_SUCCESS(s2n_find_security_policy_from_version("KMS-TLS-1-0-2018-10", &security_policy));
        EXPECT_TRUE(s2n_ecc_is_extension_required(security_policy));
        EXPECT_FALSE(s2n_pq_kem_is_extension_required(security_policy));
        EXPECT_EQUAL(0, security_policy->kem_preferences->count);
        EXPECT_NULL(security_policy->kem_preferences->kems);

#if !defined(S2N_NO_PQ)
        security_policy = NULL;
        EXPECT_SUCCESS(s2n_find_security_policy_from_version("KMS-PQ-TLS-1-0-2019-06", &security_policy));
        EXPECT_TRUE(s2n_ecc_is_extension_required(security_policy));
        EXPECT_TRUE(s2n_pq_kem_is_extension_required(security_policy));
        EXPECT_EQUAL(2, security_policy->kem_preferences->count);
        EXPECT_NOT_NULL(security_policy->kem_preferences->kems);
        EXPECT_EQUAL(security_policy->kem_preferences->kems, pq_kems_r1);

        security_policy = NULL;
        EXPECT_SUCCESS(s2n_find_security_policy_from_version("PQ-SIKE-TEST-TLS-1-0-2019-11", &security_policy));
        EXPECT_TRUE(s2n_ecc_is_extension_required(security_policy));
        EXPECT_TRUE(s2n_pq_kem_is_extension_required(security_policy));
        EXPECT_EQUAL(1, security_policy->kem_preferences->count);
        EXPECT_NOT_NULL(security_policy->kem_preferences->kems);
        EXPECT_EQUAL(security_policy->kem_preferences->kems, pq_kems_sike_r1);

        security_policy = NULL;
        EXPECT_SUCCESS(s2n_find_security_policy_from_version("PQ-SIKE-TEST-TLS-1-0-2020-02", &security_policy));
        EXPECT_TRUE(s2n_ecc_is_extension_required(security_policy));
        EXPECT_TRUE(s2n_pq_kem_is_extension_required(security_policy));
        EXPECT_EQUAL(2, security_policy->kem_preferences->count);
        EXPECT_NOT_NULL(security_policy->kem_preferences->kems);
        EXPECT_EQUAL(security_policy->kem_preferences->kems, pq_kems_sike_r2r1);

        security_policy = NULL;
        EXPECT_SUCCESS(s2n_find_security_policy_from_version("KMS-PQ-TLS-1-0-2020-02", &security_policy));
        EXPECT_TRUE(s2n_ecc_is_extension_required(security_policy));
        EXPECT_TRUE(s2n_pq_kem_is_extension_required(security_policy));
        EXPECT_EQUAL(4, security_policy->kem_preferences->count);
        EXPECT_NOT_NULL(security_policy->kem_preferences->kems);
        EXPECT_EQUAL(security_policy->kem_preferences->kems, pq_kems_r2r1);
#else
        security_policy = NULL;
        EXPECT_FAILURE_WITH_ERRNO(s2n_find_security_policy_from_version("KMS-PQ-TLS-1-0-2019-06", &security_policy), S2N_ERR_INVALID_SECURITY_POLICY);
        EXPECT_FAILURE_WITH_ERRNO(s2n_find_security_policy_from_version("PQ-SIKE-TEST-TLS-1-0-2019-11", &security_policy), S2N_ERR_INVALID_SECURITY_POLICY);
        EXPECT_FAILURE_WITH_ERRNO(s2n_find_security_policy_from_version("PQ-SIKE-TEST-TLS-1-0-2020-02", &security_policy), S2N_ERR_INVALID_SECURITY_POLICY);
        EXPECT_FAILURE_WITH_ERRNO(s2n_find_security_policy_from_version("KMS-PQ-TLS-1-0-2020-02", &security_policy), S2N_ERR_INVALID_SECURITY_POLICY);
#endif

        security_policy = NULL;
        EXPECT_SUCCESS(s2n_find_security_policy_from_version("20141001", &security_policy));
        EXPECT_FALSE(s2n_ecc_is_extension_required(security_policy));
        EXPECT_FALSE(s2n_pq_kem_is_extension_required(security_policy));
        EXPECT_EQUAL(0, security_policy->kem_preferences->count);
        EXPECT_NULL(security_policy->kem_preferences->kems);
    }

    {
        char tls12_only_security_policy_strings[][255] = {
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

        for (size_t i = 0; i < s2n_array_len(tls12_only_security_policy_strings); i++) {
            security_policy = NULL;
            EXPECT_SUCCESS(s2n_find_security_policy_from_version(tls12_only_security_policy_strings[i], &security_policy));
            EXPECT_FALSE(s2n_security_policy_supports_tls13(security_policy));
        }

        char tls13_security_policy_strings[][255] = {
            "default_tls13",
            "test_all",
            "test_all_tls13",
            "20190801",
            "20190802"
        };
        for (size_t i = 0; i < s2n_array_len(tls13_security_policy_strings); i++) {
            security_policy = NULL;
            EXPECT_SUCCESS(s2n_find_security_policy_from_version(tls13_security_policy_strings[i], &security_policy));
            EXPECT_TRUE(s2n_security_policy_supports_tls13(security_policy));
        }
    }

    /* Test that null fails */
    {
        security_policy = NULL;
        EXPECT_FALSE(s2n_ecc_is_extension_required(security_policy));
        EXPECT_FALSE(s2n_pq_kem_is_extension_required(security_policy));
        EXPECT_FALSE(s2n_security_policy_supports_tls13(security_policy));
    }

    /* Test failure case */
    {
        struct s2n_cipher_suite *fake_suites[] = {
            &s2n_ecdhe_bike_rsa_with_aes_256_gcm_sha384,
        };

        const struct s2n_cipher_preferences fake_cipher_preference = {
            .count = 1,
            .suites = fake_suites,
        };

        const struct s2n_kem_preferences fake_kem_preference = {
            .count = 1,
            .kems = NULL,
        };

        const struct s2n_security_policy fake_security_policy = {
            .minimum_protocol_version = S2N_TLS10,
            .cipher_preferences = &fake_cipher_preference,
            .kem_preferences = &fake_kem_preference,
        };

        security_policy = &fake_security_policy;
        EXPECT_FALSE(s2n_ecc_is_extension_required(security_policy));
        EXPECT_FALSE(s2n_pq_kem_is_extension_required(security_policy));
        EXPECT_FALSE(s2n_security_policy_supports_tls13(security_policy));
    }
    {
        struct s2n_config *config = s2n_config_new();

        EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, "default"));
        EXPECT_EQUAL(config->security_policy, &security_policy_20170210);
        EXPECT_EQUAL(config->security_policy->cipher_preferences, &cipher_preferences_20170210);
        EXPECT_EQUAL(config->security_policy->kem_preferences, &kem_preferences_null);
        EXPECT_EQUAL(config->security_policy->signature_preferences, &s2n_signature_preferences_20140601);
        EXPECT_EQUAL(config->security_policy->ecc_preferences, &s2n_ecc_preferences_20140601);

        EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, "20170210"));
        EXPECT_EQUAL(config->security_policy, &security_policy_20170210);
        EXPECT_EQUAL(config->security_policy->cipher_preferences, &cipher_preferences_20170210);
        EXPECT_EQUAL(config->security_policy->kem_preferences, &kem_preferences_null);
        EXPECT_EQUAL(config->security_policy->signature_preferences, &s2n_signature_preferences_20140601);
        EXPECT_EQUAL(config->security_policy->ecc_preferences, &s2n_ecc_preferences_20140601);

        EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, "default_tls13"));
        EXPECT_EQUAL(config->security_policy, &security_policy_20190801);
        EXPECT_EQUAL(config->security_policy->cipher_preferences, &cipher_preferences_20190801);
        EXPECT_EQUAL(config->security_policy->kem_preferences, &kem_preferences_null);
        EXPECT_EQUAL(config->security_policy->signature_preferences, &s2n_signature_preferences_20200207);
        EXPECT_EQUAL(config->security_policy->ecc_preferences, &s2n_ecc_preferences_20200310);

        EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, "20190801"));
        EXPECT_EQUAL(config->security_policy, &security_policy_20190801);
        EXPECT_EQUAL(config->security_policy->cipher_preferences, &cipher_preferences_20190801);
        EXPECT_EQUAL(config->security_policy->kem_preferences, &kem_preferences_null);
        EXPECT_EQUAL(config->security_policy->signature_preferences, &s2n_signature_preferences_20200207);
        EXPECT_EQUAL(config->security_policy->ecc_preferences, &s2n_ecc_preferences_20200310);

        EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, "null"));
        EXPECT_EQUAL(config->security_policy, &security_policy_null);
        EXPECT_EQUAL(config->security_policy->cipher_preferences, &cipher_preferences_null);
        EXPECT_EQUAL(config->security_policy->kem_preferences, &kem_preferences_null);
        EXPECT_EQUAL(config->security_policy->signature_preferences, &s2n_signature_preferences_null);
        EXPECT_EQUAL(config->security_policy->ecc_preferences, &s2n_ecc_preferences_null);

        EXPECT_FAILURE(s2n_config_set_cipher_preferences(config, NULL));

        EXPECT_FAILURE_WITH_ERRNO(s2n_config_set_cipher_preferences(config, "notathing"),
                S2N_ERR_INVALID_SECURITY_POLICY);

        s2n_config_free(config);
    }
    {
        struct s2n_config *config = s2n_config_new();

        struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT);
        s2n_connection_set_config(conn, config);

        EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(conn, "default"));
        EXPECT_SUCCESS(s2n_connection_get_security_policy(conn, &security_policy));
        EXPECT_EQUAL(security_policy, &security_policy_20170210);
        EXPECT_EQUAL(security_policy->cipher_preferences, &cipher_preferences_20170210);
        EXPECT_EQUAL(security_policy->kem_preferences, &kem_preferences_null);
        EXPECT_EQUAL(security_policy->signature_preferences, &s2n_signature_preferences_20140601);
        EXPECT_EQUAL(security_policy->ecc_preferences, &s2n_ecc_preferences_20140601);

        EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(conn, "20170210"));
        EXPECT_SUCCESS(s2n_connection_get_security_policy(conn, &security_policy));
        EXPECT_EQUAL(security_policy, &security_policy_20170210);
        EXPECT_EQUAL(security_policy->cipher_preferences, &cipher_preferences_20170210);
        EXPECT_EQUAL(security_policy->kem_preferences, &kem_preferences_null);
        EXPECT_EQUAL(security_policy->signature_preferences, &s2n_signature_preferences_20140601);
        EXPECT_EQUAL(security_policy->ecc_preferences, &s2n_ecc_preferences_20140601);

        EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(conn, "default_tls13"));
        EXPECT_SUCCESS(s2n_connection_get_security_policy(conn, &security_policy));
        EXPECT_EQUAL(security_policy, &security_policy_20190801);
        EXPECT_EQUAL(security_policy->cipher_preferences, &cipher_preferences_20190801);
        EXPECT_EQUAL(security_policy->kem_preferences, &kem_preferences_null);
        EXPECT_EQUAL(security_policy->signature_preferences, &s2n_signature_preferences_20200207);
        EXPECT_EQUAL(security_policy->ecc_preferences, &s2n_ecc_preferences_20200310);

        EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(conn, "20190801"));
        EXPECT_SUCCESS(s2n_connection_get_security_policy(conn, &security_policy));
        EXPECT_EQUAL(security_policy, &security_policy_20190801);
        EXPECT_EQUAL(security_policy->cipher_preferences, &cipher_preferences_20190801);
        EXPECT_EQUAL(security_policy->kem_preferences, &kem_preferences_null);
        EXPECT_EQUAL(security_policy->signature_preferences, &s2n_signature_preferences_20200207);
        EXPECT_EQUAL(security_policy->ecc_preferences, &s2n_ecc_preferences_20200310);

        EXPECT_FAILURE_WITH_ERRNO(s2n_connection_set_cipher_preferences(conn, "notathing"),
                S2N_ERR_INVALID_SECURITY_POLICY);

        s2n_config_free(config);
        s2n_connection_free(conn);
    }

    /* All signature preferences are valid */
    {
        for (int i = 0; security_policy_selection[i].version != NULL; i++) {
            security_policy = security_policy_selection[i].security_policy;
            EXPECT_NOT_NULL(security_policy);
            EXPECT_NOT_NULL(security_policy->signature_preferences);

            for (int j = 0; j < security_policy->signature_preferences->count; j++) {
                const struct s2n_signature_scheme *scheme = security_policy->signature_preferences->signature_schemes[j];

                EXPECT_NOT_NULL(scheme);

                uint8_t max_version = scheme->maximum_protocol_version;
                uint8_t min_version = scheme->minimum_protocol_version;

                EXPECT_TRUE(max_version == S2N_UNKNOWN_PROTOCOL_VERSION || min_version <= max_version);

                /* If scheme will be used for tls1.3 */
                if (max_version == S2N_UNKNOWN_PROTOCOL_VERSION || max_version >= S2N_TLS13) {
                    EXPECT_NOT_EQUAL(scheme->hash_alg, S2N_HASH_SHA1);
                    EXPECT_NOT_EQUAL(scheme->sig_alg, S2N_SIGNATURE_RSA);
                    if (scheme->sig_alg == S2N_SIGNATURE_ECDSA) {
                        EXPECT_NOT_NULL(scheme->signature_curve);
                    }
                }

                /* If scheme will be used for pre-tls1.3 */
                if (min_version < S2N_TLS13) {
                    EXPECT_NULL(scheme->signature_curve);
                    EXPECT_NOT_EQUAL(scheme->sig_alg, S2N_SIGNATURE_RSA_PSS_PSS);
                }
            }
        }
    }
    
    /* Failure case when s2n_ecc_preference lists contains a curve not present in s2n_all_supported_curves_list */
    {
        const struct s2n_ecc_named_curve test_curve = {
            .iana_id = 12345, 
            .libcrypto_nid = 0, 
            .name = "test_curve", 
            .share_size = 0
        };

        const struct s2n_ecc_named_curve *const s2n_ecc_pref_list_test[] = {
            &test_curve,
        };

        const struct s2n_ecc_preferences s2n_ecc_preferences_new_list = {
            .count = s2n_array_len(s2n_ecc_pref_list_test),
            .ecc_curves = s2n_ecc_pref_list_test,
        };

        EXPECT_FAILURE(s2n_check_ecc_preferences_curves_list(&s2n_ecc_preferences_new_list));
    }

    END_TEST();
}
