/*
 * Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

struct s2n_cipher_preferences {
    uint8_t count;
    struct s2n_cipher_suite **suites;
    int minimum_protocol_version;
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
extern const struct s2n_cipher_preferences cipher_preferences_test_all;
extern const struct s2n_cipher_preferences cipher_preferences_test_all_fips;
extern const struct s2n_cipher_preferences cipher_preferences_test_all_ecdsa;
extern const struct s2n_cipher_preferences cipher_preferences_test_ecdsa_priority;
extern const struct s2n_cipher_preferences cipher_preferences_test_tls13_null_key_exchange_alg;

/* See https://docs.aws.amazon.com/elasticloadbalancing/latest/application/create-https-listener.html */
extern const struct s2n_cipher_preferences elb_security_policy_2015_04;
extern const struct s2n_cipher_preferences elb_security_policy_2016_08;
extern const struct s2n_cipher_preferences elb_security_policy_tls_1_2_2017_01;
extern const struct s2n_cipher_preferences elb_security_policy_tls_1_1_2017_01;
extern const struct s2n_cipher_preferences elb_security_policy_tls_1_2_ext_2018_06;
extern const struct s2n_cipher_preferences elb_security_policy_fs_2018_06;

extern const struct s2n_cipher_preferences elb_security_policy_fs_1_2_2019_08;
extern const struct s2n_cipher_preferences elb_security_policy_fs_1_1_2019_08;
extern const struct s2n_cipher_preferences elb_security_policy_fs_1_2_res_2019_08;

extern int s2n_cipher_preferences_init();
extern int s2n_find_cipher_pref_from_version(const char *version, const struct s2n_cipher_preferences **cipher_preferences);
extern int s2n_config_set_cipher_preferences(struct s2n_config *config, const char *version);
extern int s2n_ecc_extension_required(const struct s2n_cipher_preferences *preferences);
extern int s2n_pq_kem_extension_required(const struct s2n_cipher_preferences *preferences);
