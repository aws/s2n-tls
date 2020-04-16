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
#include "tls/s2n_cipher_preferences.h"
#include "tls/s2n_kem_preferences.h"

struct s2n_security_policy {
    uint8_t minimum_protocol_version;
    const struct s2n_cipher_preferences *cipher_preferences;
    const struct s2n_kem_preferences *kem_preferences;
};

const struct s2n_security_policy security_policy_20140601;
const struct s2n_security_policy security_policy_20141001;
const struct s2n_security_policy security_policy_20150202;
const struct s2n_security_policy security_policy_20150214;
const struct s2n_security_policy security_policy_20150306;
const struct s2n_security_policy security_policy_20160411;
const struct s2n_security_policy security_policy_20160804;
const struct s2n_security_policy security_policy_20160824;
const struct s2n_security_policy security_policy_20170210;
const struct s2n_security_policy security_policy_20170328;
const struct s2n_security_policy security_policy_20170405;
const struct s2n_security_policy security_policy_20170718;
const struct s2n_security_policy security_policy_20190214;
const struct s2n_security_policy security_policy_test_all;

const struct s2n_security_policy security_policy_test_all_tls12;
const struct s2n_security_policy security_policy_test_all_fips;
const struct s2n_security_policy security_policy_test_all_ecdsa;
const struct s2n_security_policy security_policy_test_ecdsa_priority;
const struct s2n_security_policy security_policy_test_all_rsa_kex;
const struct s2n_security_policy security_policy_test_all_tls13;

/* See https://docs.aws.amazon.com/elasticloadbalancing/latest/application/create-https-listener.html */
const struct s2n_security_policy security_policy_elb_2015_04;
const struct s2n_security_policy security_policy_elb_2016_08;
const struct s2n_security_policy security_policy_elb_tls_1_2_2017_01;
const struct s2n_security_policy security_policy_elb_tls_1_1_2017_01;
const struct s2n_security_policy security_policy_elb_tls_1_2_ext_2018_06;
const struct s2n_security_policy security_policy_elb_fs_2018_06;
const struct s2n_security_policy security_policy_elb_fs_1_2_2019_08;
const struct s2n_security_policy security_policy_elb_fs_1_1_2019_08;
const struct s2n_security_policy security_policy_elb_fs_1_2_res_2019_08;

#if !defined(S2N_NO_PQ)
const struct s2n_security_policy security_policy_kms_pq_tls_1_0_2019_06;
const struct s2n_security_policy security_policy_kms_pq_tls_1_0_2020_02;
const struct s2n_security_policy security_policy_pq_sike_test_tls_1_0_2019_11;
const struct s2n_security_policy security_policy_pq_sike_test_tls_1_0_2020_02;
#endif

const struct s2n_security_policy security_policy_cloudfront_upstream;
const struct s2n_security_policy security_policy_cloudfront_upstream_tls10;
const struct s2n_security_policy security_policy_cloudfront_upstream_tls12;
const struct s2n_security_policy security_policy_cloudfront_ssl_v_3;
const struct s2n_security_policy security_policy_cloudfront_tls_1_0_2014;
const struct s2n_security_policy security_policy_cloudfront_tls_1_0_2016;
const struct s2n_security_policy security_policy_cloudfront_tls_1_1_2016;
const struct s2n_security_policy security_policy_cloudfront_tls_1_2_2018;
const struct s2n_security_policy security_policy_cloudfront_tls_1_2_2019;
const struct s2n_security_policy security_policy_cloudfront_tls_1_2_2020;

const struct s2n_security_policy security_policy_kms_tls_1_0_2018_10;
const struct s2n_security_policy security_policy_kms_fips_tls_1_2_2018_10;

const struct s2n_security_policy security_policy_20190120;
const struct s2n_security_policy security_policy_20190121;
const struct s2n_security_policy security_policy_20190122;

int s2n_security_policies_init();
int s2n_config_set_cipher_preferences(struct s2n_config *config, const char *version);
int s2n_connection_set_cipher_preferences(struct s2n_connection *conn, const char *version);
int s2n_ecc_is_extension_required(const struct s2n_security_policy *security_policy);
int s2n_pq_kem_is_extension_required(const struct s2n_security_policy *security_policy);
bool s2n_security_policy_supports_tls13(const struct s2n_security_policy *security_policy);
int s2n_find_security_policy_from_version(const char *version, const struct s2n_security_policy **security_policy);
