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

#pragma once

#include <stdint.h>

#include "policy/s2n_security_policy.h"
#include "tls/s2n_certificate_keys.h"
#include "tls/s2n_cipher_preferences.h"
#include "tls/s2n_ecc_preferences.h"
#include "tls/s2n_kem_preferences.h"
#include "tls/s2n_security_rules.h"
#include "tls/s2n_signature_scheme.h"

/* Kept up-to-date by s2n_security_policies_test */
#define NUM_RSA_PSS_SCHEMES 6

struct s2n_security_policy_selection {
    const char *version;
    const struct s2n_security_policy *security_policy;
    unsigned ecc_extension_required : 1;
    unsigned pq_kem_extension_required : 1;
    unsigned supports_tls13 : 1;
};

extern struct s2n_security_policy_selection security_policy_selection[];
extern const char *deprecated_security_policies[];
extern const size_t deprecated_security_policies_len;

/* Defaults as of 05/24 */
extern const struct s2n_security_policy security_policy_20240501;
extern const struct s2n_security_policy security_policy_20240502;
extern const struct s2n_security_policy security_policy_20240503;

extern const struct s2n_security_policy security_policy_20241106;
extern const struct s2n_security_policy security_policy_20140601;
extern const struct s2n_security_policy security_policy_20141001;
extern const struct s2n_security_policy security_policy_20150202;
extern const struct s2n_security_policy security_policy_20150214;
extern const struct s2n_security_policy security_policy_20150306;
extern const struct s2n_security_policy security_policy_20160411;
extern const struct s2n_security_policy security_policy_20160804;
extern const struct s2n_security_policy security_policy_20160824;
extern const struct s2n_security_policy security_policy_20170210;
extern const struct s2n_security_policy security_policy_20170328;
extern const struct s2n_security_policy security_policy_20170328_gcm;
extern const struct s2n_security_policy security_policy_20170405;
extern const struct s2n_security_policy security_policy_20170405_gcm;
extern const struct s2n_security_policy security_policy_20170718;
extern const struct s2n_security_policy security_policy_20170718_gcm;
extern const struct s2n_security_policy security_policy_20190214;
extern const struct s2n_security_policy security_policy_20190214_gcm;
extern const struct s2n_security_policy security_policy_20190801;
extern const struct s2n_security_policy security_policy_20190802;
extern const struct s2n_security_policy security_policy_20230317;
extern const struct s2n_security_policy security_policy_20240331;
extern const struct s2n_security_policy security_policy_20240417;
extern const struct s2n_security_policy security_policy_20240416;
extern const struct s2n_security_policy security_policy_20240603;
extern const struct s2n_security_policy security_policy_20240730;
extern const struct s2n_security_policy security_policy_20241001;
extern const struct s2n_security_policy security_policy_20241001_pq_mixed;
extern const struct s2n_security_policy security_policy_20250211;
extern const struct s2n_security_policy security_policy_20250414;

extern const struct s2n_security_policy security_policy_rfc9151;
extern const struct s2n_security_policy security_policy_test_all;

extern const struct s2n_security_policy security_policy_test_all_tls12;
extern const struct s2n_security_policy security_policy_test_all_fips;
extern const struct s2n_security_policy security_policy_test_all_ecdsa;
extern const struct s2n_security_policy security_policy_test_ecdsa_priority;
extern const struct s2n_security_policy security_policy_test_all_rsa_kex;
extern const struct s2n_security_policy security_policy_test_all_tls13;

/* See https://docs.aws.amazon.com/elasticloadbalancing/latest/application/create-https-listener.html */
extern const struct s2n_security_policy security_policy_elb_2015_04;
extern const struct s2n_security_policy security_policy_elb_2016_08;
extern const struct s2n_security_policy security_policy_elb_tls_1_2_2017_01;
extern const struct s2n_security_policy security_policy_elb_tls_1_1_2017_01;
extern const struct s2n_security_policy security_policy_elb_tls_1_2_ext_2018_06;
extern const struct s2n_security_policy security_policy_elb_fs_2018_06;
extern const struct s2n_security_policy security_policy_elb_fs_1_2_2019_08;
extern const struct s2n_security_policy security_policy_elb_fs_1_1_2019_08;
extern const struct s2n_security_policy security_policy_elb_fs_1_2_res_2019_08;

extern const struct s2n_security_policy security_policy_aws_crt_sdk_ssl_v3;
extern const struct s2n_security_policy security_policy_aws_crt_sdk_tls_10;
extern const struct s2n_security_policy security_policy_aws_crt_sdk_tls_11;
extern const struct s2n_security_policy security_policy_aws_crt_sdk_tls_12;
extern const struct s2n_security_policy security_policy_aws_crt_sdk_tls_12_06_23;
extern const struct s2n_security_policy security_policy_aws_crt_sdk_tls_12_06_23_pq;
extern const struct s2n_security_policy security_policy_aws_crt_sdk_tls_13;

extern const struct s2n_security_policy security_policy_kms_pq_tls_1_0_2019_06;
extern const struct s2n_security_policy security_policy_kms_pq_tls_1_0_2020_02;
extern const struct s2n_security_policy security_policy_kms_pq_tls_1_0_2020_07;
extern const struct s2n_security_policy security_policy_pq_tls_1_0_2020_12;
extern const struct s2n_security_policy security_policy_pq_tls_1_1_2021_05_17;
extern const struct s2n_security_policy security_policy_pq_tls_1_0_2021_05_18;
extern const struct s2n_security_policy security_policy_pq_tls_1_0_2021_05_19;
extern const struct s2n_security_policy security_policy_pq_tls_1_0_2021_05_20;
extern const struct s2n_security_policy security_policy_pq_tls_1_1_2021_05_21;
extern const struct s2n_security_policy security_policy_pq_tls_1_0_2021_05_22;
extern const struct s2n_security_policy security_policy_pq_tls_1_0_2021_05_23;
extern const struct s2n_security_policy security_policy_pq_tls_1_0_2021_05_24;
extern const struct s2n_security_policy security_policy_pq_tls_1_0_2021_05_25;
extern const struct s2n_security_policy security_policy_pq_tls_1_0_2021_05_26;
extern const struct s2n_security_policy security_policy_pq_tls_1_0_2023_01_24;
extern const struct s2n_security_policy security_policy_pq_tls_1_2_2023_04_07;
extern const struct s2n_security_policy security_policy_pq_tls_1_2_2023_04_08;
extern const struct s2n_security_policy security_policy_pq_tls_1_2_2023_04_09;
extern const struct s2n_security_policy security_policy_pq_tls_1_2_2023_04_10;
extern const struct s2n_security_policy security_policy_pq_tls_1_3_2023_06_01;
extern const struct s2n_security_policy security_policy_pq_tls_1_2_2023_10_07;
extern const struct s2n_security_policy security_policy_pq_tls_1_2_2023_10_08;
extern const struct s2n_security_policy security_policy_pq_tls_1_2_2023_10_09;
extern const struct s2n_security_policy security_policy_pq_tls_1_2_2023_10_10;
extern const struct s2n_security_policy security_policy_pq_tls_1_2_2024_10_07;
extern const struct s2n_security_policy security_policy_pq_tls_1_2_2024_10_08;
extern const struct s2n_security_policy security_policy_pq_tls_1_2_2024_10_08_gcm;
extern const struct s2n_security_policy security_policy_pq_tls_1_2_2024_10_09;

extern const struct s2n_security_policy security_policy_cloudfront_upstream;
extern const struct s2n_security_policy security_policy_cloudfront_upstream_tls10;
extern const struct s2n_security_policy security_policy_cloudfront_upstream_tls12;
extern const struct s2n_security_policy security_policy_cloudfront_ssl_v_3;
extern const struct s2n_security_policy security_policy_cloudfront_tls_1_0_2014;
extern const struct s2n_security_policy security_policy_cloudfront_tls_1_0_2016;
extern const struct s2n_security_policy security_policy_cloudfront_tls_1_1_2016;
extern const struct s2n_security_policy security_policy_cloudfront_tls_1_2_2017;
extern const struct s2n_security_policy security_policy_cloudfront_tls_1_2_2018;
extern const struct s2n_security_policy security_policy_cloudfront_tls_1_2_2019;
extern const struct s2n_security_policy security_policy_cloudfront_tls_1_2_2021;
extern const struct s2n_security_policy security_policy_cloudfront_tls_1_2_2021_chacha20_boosted;

extern const struct s2n_security_policy security_policy_kms_tls_1_0_2018_10;
extern const struct s2n_security_policy security_policy_kms_tls_1_2_2023_06;
extern const struct s2n_security_policy security_policy_kms_fips_tls_1_2_2018_10;
extern const struct s2n_security_policy security_policy_kms_fips_tls_1_2_2024_10;

extern const struct s2n_security_policy security_policy_20190120;
extern const struct s2n_security_policy security_policy_20190121;
extern const struct s2n_security_policy security_policy_20190122;

extern const struct s2n_security_policy security_policy_null;

int s2n_security_policies_init();
bool s2n_ecc_is_extension_required(const struct s2n_security_policy *security_policy);
bool s2n_pq_kem_is_extension_required(const struct s2n_security_policy *security_policy);
int s2n_find_security_policy_from_version(const char *version, const struct s2n_security_policy **security_policy);
int s2n_validate_kem_preferences(const struct s2n_kem_preferences *kem_preferences, bool pq_kem_extension_required);
S2N_RESULT s2n_validate_certificate_signature_preferences(const struct s2n_signature_preferences *s2n_certificate_signature_preferences);
S2N_RESULT s2n_security_policy_get_version(const struct s2n_security_policy *security_policy,
        const char **version);
