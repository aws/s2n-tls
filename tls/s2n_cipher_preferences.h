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
#include "tls/s2n_cipher_suites.h"
#include "tls/s2n_kem.h"
#include "tls/s2n_tls13.h"

struct s2n_cipher_preferences {
    uint8_t count;
    struct s2n_cipher_suite **suites;
};

extern const struct s2n_cipher_preferences cipher_preferences_20140601;
extern const struct s2n_cipher_preferences cipher_preferences_20141001;
extern const struct s2n_cipher_preferences cipher_preferences_20150202;
extern const struct s2n_cipher_preferences cipher_preferences_20150214;
extern const struct s2n_cipher_preferences cipher_preferences_20150306;
extern const struct s2n_cipher_preferences cipher_preferences_20160411;
extern const struct s2n_cipher_preferences cipher_preferences_20160804;
extern const struct s2n_cipher_preferences cipher_preferences_20160824;
extern const struct s2n_cipher_preferences cipher_preferences_20170210;
extern const struct s2n_cipher_preferences cipher_preferences_20170328;
extern const struct s2n_cipher_preferences cipher_preferences_20170405;
extern const struct s2n_cipher_preferences cipher_preferences_20170718;
extern const struct s2n_cipher_preferences cipher_preferences_20190214;
extern const struct s2n_cipher_preferences cipher_preferences_20190801;
extern const struct s2n_cipher_preferences cipher_preferences_20190120;
extern const struct s2n_cipher_preferences cipher_preferences_20190121;
extern const struct s2n_cipher_preferences cipher_preferences_20190122;
extern const struct s2n_cipher_preferences cipher_preferences_test_all;

extern const struct s2n_cipher_preferences cipher_preferences_test_all_tls12;
extern const struct s2n_cipher_preferences cipher_preferences_test_all_fips;
extern const struct s2n_cipher_preferences cipher_preferences_test_all_ecdsa;
extern const struct s2n_cipher_preferences cipher_preferences_test_ecdsa_priority;
extern const struct s2n_cipher_preferences cipher_preferences_test_all_rsa_kex;
extern const struct s2n_cipher_preferences cipher_preferences_test_all_tls13;

/* See https://docs.aws.amazon.com/elasticloadbalancing/latest/application/create-https-listener.html */
extern const struct s2n_cipher_preferences elb_security_policy_2015_04;
extern const struct s2n_cipher_preferences elb_security_policy_2016_08;

extern const struct s2n_cipher_preferences elb_security_policy_tls_1_1_2017_01;
extern const struct s2n_cipher_preferences elb_security_policy_tls_1_2_2017_01;
extern const struct s2n_cipher_preferences elb_security_policy_tls_1_2_ext_2018_06;

extern const struct s2n_cipher_preferences elb_security_policy_fs_2018_06;
extern const struct s2n_cipher_preferences elb_security_policy_fs_1_2_2019_08;
extern const struct s2n_cipher_preferences elb_security_policy_fs_1_1_2019_08;
extern const struct s2n_cipher_preferences elb_security_policy_fs_1_2_Res_2019_08;

/* CloudFront upstream */
extern const struct s2n_cipher_preferences cipher_preferences_cloudfront_upstream;
extern const struct s2n_cipher_preferences cipher_preferences_cloudfront_upstream_tls10;
extern const struct s2n_cipher_preferences cipher_preferences_cloudfront_upstream_tls11;
extern const struct s2n_cipher_preferences cipher_preferences_cloudfront_upstream_tls12;
/* CloudFront viewer facing */
extern const struct s2n_cipher_preferences cipher_preferences_cloudfront_ssl_v_3;
extern const struct s2n_cipher_preferences cipher_preferences_cloudfront_tls_1_0_2014;
extern const struct s2n_cipher_preferences cipher_preferences_cloudfront_tls_1_0_2016;
extern const struct s2n_cipher_preferences cipher_preferences_cloudfront_tls_1_1_2016;
extern const struct s2n_cipher_preferences cipher_preferences_cloudfront_tls_1_2_2018;
extern const struct s2n_cipher_preferences cipher_preferences_cloudfront_tls_1_2_2019;
extern const struct s2n_cipher_preferences cipher_preferences_cloudfront_tls_1_2_2021;

/* CloudFront viewer facing legacy TLS 1.2 policies */
extern const struct s2n_cipher_preferences cipher_preferences_cloudfront_ssl_v_3_legacy;
extern const struct s2n_cipher_preferences cipher_preferences_cloudfront_tls_1_0_2014_legacy;
extern const struct s2n_cipher_preferences cipher_preferences_cloudfront_tls_1_0_2016_legacy;
extern const struct s2n_cipher_preferences cipher_preferences_cloudfront_tls_1_1_2016_legacy;
extern const struct s2n_cipher_preferences cipher_preferences_cloudfront_tls_1_2_2018_legacy;
extern const struct s2n_cipher_preferences cipher_preferences_cloudfront_tls_1_2_2019_legacy;

extern const struct s2n_cipher_preferences cipher_preferences_kms_tls_1_0_2018_10;

extern const struct s2n_cipher_preferences cipher_preferences_kms_pq_tls_1_0_2019_06;
extern const struct s2n_cipher_preferences cipher_preferences_kms_pq_tls_1_0_2020_02;
extern const struct s2n_cipher_preferences cipher_preferences_kms_pq_tls_1_0_2020_07;
extern const struct s2n_cipher_preferences cipher_preferences_pq_sike_test_tls_1_0_2019_11;
extern const struct s2n_cipher_preferences cipher_preferences_pq_sike_test_tls_1_0_2020_02;
extern const struct s2n_cipher_preferences cipher_preferences_pq_tls_1_0_2020_12;

extern const struct s2n_cipher_preferences cipher_preferences_kms_fips_tls_1_2_2018_10;
extern const struct s2n_cipher_preferences cipher_preferences_null;

