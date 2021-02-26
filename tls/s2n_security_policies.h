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
#include "tls/s2n_signature_scheme.h"
#include "tls/s2n_ecc_preferences.h"

/* Kept up-to-date by s2n_security_policies_test */
#define NUM_RSA_PSS_SCHEMES 6

struct s2n_security_policy {
    uint8_t minimum_protocol_version;
    const struct s2n_cipher_preferences *cipher_preferences;
    const struct s2n_kem_preferences *kem_preferences;
    const struct s2n_signature_preferences *signature_preferences;
    const struct s2n_signature_preferences *certificate_signature_preferences;
    const struct s2n_ecc_preferences *ecc_preferences;
};

struct s2n_security_policy_selection {
    const char *version;
    const struct s2n_security_policy *security_policy;
    unsigned ecc_extension_required:1;
    unsigned pq_kem_extension_required:1;
    unsigned supports_tls13:1;
};

extern struct s2n_security_policy_selection security_policy_selection[];

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
extern const struct s2n_security_policy security_policy_20170405;
extern const struct s2n_security_policy security_policy_20170718;
extern const struct s2n_security_policy security_policy_20190214;
extern const struct s2n_security_policy security_policy_20190801;
extern const struct s2n_security_policy security_policy_20190802;
extern const struct s2n_security_policy security_policy_20201110;
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

extern const struct s2n_security_policy security_policy_kms_pq_tls_1_0_2019_06;
extern const struct s2n_security_policy security_policy_kms_pq_tls_1_0_2020_02;
extern const struct s2n_security_policy security_policy_kms_pq_tls_1_0_2020_07;
extern const struct s2n_security_policy security_policy_pq_sike_test_tls_1_0_2019_11;
extern const struct s2n_security_policy security_policy_pq_sike_test_tls_1_0_2020_02;
extern const struct s2n_security_policy security_policy_pq_tls_1_0_2020_12;

extern const struct s2n_security_policy security_policy_cloudfront_upstream;
extern const struct s2n_security_policy security_policy_cloudfront_upstream_tls10;
extern const struct s2n_security_policy security_policy_cloudfront_upstream_tls12;
extern const struct s2n_security_policy security_policy_cloudfront_ssl_v_3;
extern const struct s2n_security_policy security_policy_cloudfront_tls_1_0_2014;
extern const struct s2n_security_policy security_policy_cloudfront_tls_1_0_2016;
extern const struct s2n_security_policy security_policy_cloudfront_tls_1_1_2016;
extern const struct s2n_security_policy security_policy_cloudfront_tls_1_2_2018;
extern const struct s2n_security_policy security_policy_cloudfront_tls_1_2_2019;
extern const struct s2n_security_policy security_policy_cloudfront_tls_1_2_2021;

extern const struct s2n_security_policy security_policy_kms_tls_1_0_2018_10;
extern const struct s2n_security_policy security_policy_kms_fips_tls_1_2_2018_10;

extern const struct s2n_security_policy security_policy_20190120;
extern const struct s2n_security_policy security_policy_20190121;
extern const struct s2n_security_policy security_policy_20190122;

extern const struct s2n_security_policy security_policy_null;

int s2n_security_policies_init();
int s2n_config_set_cipher_preferences(struct s2n_config *config, const char *version);
int s2n_connection_set_cipher_preferences(struct s2n_connection *conn, const char *version);
bool s2n_ecc_is_extension_required(const struct s2n_security_policy *security_policy);
bool s2n_pq_kem_is_extension_required(const struct s2n_security_policy *security_policy);
bool s2n_security_policy_supports_tls13(const struct s2n_security_policy *security_policy);
int s2n_find_security_policy_from_version(const char *version, const struct s2n_security_policy **security_policy);
int s2n_validate_kem_preferences(const struct s2n_kem_preferences *kem_preferences, bool pq_kem_extension_required);
S2N_RESULT s2n_validate_certificate_signature_preferences(const struct s2n_signature_preferences *s2n_certificate_signature_preferences);
