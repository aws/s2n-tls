/*
 * Copyright 2017 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

#include <strings.h>
#include <stdint.h>
#include <s2n.h>
#include "tls/s2n_cipher_preferences.h"
#include "tls/s2n_config.h"

#include "error/s2n_errno.h"
#include "utils/s2n_safety.h"

/* s2n's list of cipher suites, in order of preference, as of 2014-06-01 */
struct s2n_cipher_suite *cipher_suites_20140601[] = {
    &s2n_dhe_rsa_with_aes_128_cbc_sha256,
    &s2n_dhe_rsa_with_aes_128_cbc_sha,
    &s2n_dhe_rsa_with_3des_ede_cbc_sha,
    &s2n_rsa_with_aes_128_cbc_sha256,
    &s2n_rsa_with_aes_128_cbc_sha,
    &s2n_rsa_with_3des_ede_cbc_sha,
    &s2n_rsa_with_rc4_128_sha,
    &s2n_rsa_with_rc4_128_md5
};

const struct s2n_cipher_preferences cipher_preferences_20140601 = {
    .count = sizeof(cipher_suites_20140601) / sizeof(cipher_suites_20140601[0]),
    .suites = cipher_suites_20140601,
    .minimum_protocol_version = S2N_SSLv3
};

/* Disable SSLv3 due to POODLE */
const struct s2n_cipher_preferences cipher_preferences_20141001 = {
    .count = sizeof(cipher_suites_20140601) / sizeof(cipher_suites_20140601[0]),
    .suites = cipher_suites_20140601,
    .minimum_protocol_version = S2N_TLS10
};

/* Disable RC4 */
struct s2n_cipher_suite *cipher_suites_20150202[] = {
    &s2n_dhe_rsa_with_aes_128_cbc_sha256,
    &s2n_dhe_rsa_with_aes_128_cbc_sha,
    &s2n_dhe_rsa_with_3des_ede_cbc_sha,
    &s2n_rsa_with_aes_128_cbc_sha256,
    &s2n_rsa_with_aes_128_cbc_sha,
    &s2n_rsa_with_3des_ede_cbc_sha
};

const struct s2n_cipher_preferences cipher_preferences_20150202 = {
    .count = sizeof(cipher_suites_20150202) / sizeof(cipher_suites_20150202[0]),
    .suites = cipher_suites_20150202,
    .minimum_protocol_version = S2N_TLS10
};

/* Support AES-GCM modes */
struct s2n_cipher_suite *cipher_suites_20150214[] = {
    &s2n_dhe_rsa_with_aes_128_gcm_sha256,
    &s2n_dhe_rsa_with_aes_128_cbc_sha256,
    &s2n_dhe_rsa_with_aes_128_cbc_sha,
    &s2n_dhe_rsa_with_3des_ede_cbc_sha,
    &s2n_rsa_with_aes_128_gcm_sha256,
    &s2n_rsa_with_aes_128_cbc_sha256,
    &s2n_rsa_with_aes_128_cbc_sha,
    &s2n_rsa_with_3des_ede_cbc_sha
};

const struct s2n_cipher_preferences cipher_preferences_20150214 = {
    .count = sizeof(cipher_suites_20150214) / sizeof(cipher_suites_20150214[0]),
    .suites = cipher_suites_20150214,
    .minimum_protocol_version = S2N_TLS10
};

/* Make a CBC cipher #1 to avoid negotiating GCM with buggy Java clients */
struct s2n_cipher_suite *cipher_suites_20160411[] = {
    &s2n_ecdhe_rsa_with_aes_128_cbc_sha,
    &s2n_ecdhe_rsa_with_aes_128_gcm_sha256,
    &s2n_ecdhe_rsa_with_aes_256_gcm_sha384,
    &s2n_ecdhe_rsa_with_aes_128_cbc_sha256,
    &s2n_ecdhe_rsa_with_aes_256_cbc_sha,
    &s2n_ecdhe_rsa_with_aes_256_cbc_sha384,
    &s2n_rsa_with_aes_128_cbc_sha,
    &s2n_rsa_with_aes_128_gcm_sha256,
    &s2n_rsa_with_aes_256_gcm_sha384,
    &s2n_rsa_with_aes_128_cbc_sha256,
    &s2n_rsa_with_aes_256_cbc_sha,
    &s2n_rsa_with_aes_256_cbc_sha256,
    &s2n_rsa_with_3des_ede_cbc_sha,
};

const struct s2n_cipher_preferences cipher_preferences_20160411 = {
    .count = sizeof(cipher_suites_20160411) / sizeof(cipher_suites_20160411[0]),
    .suites = cipher_suites_20160411,
    .minimum_protocol_version = S2N_TLS10
};

/* Use ECDHE instead of plain DHE. Prioritize ECDHE in favour of non ECDHE; GCM in favour of CBC; AES128 in favour of AES256. */
struct s2n_cipher_suite *cipher_suites_20150306[] = {
    &s2n_ecdhe_rsa_with_aes_128_gcm_sha256,
    &s2n_ecdhe_rsa_with_aes_256_gcm_sha384,
    &s2n_ecdhe_rsa_with_aes_128_cbc_sha,
    &s2n_ecdhe_rsa_with_aes_128_cbc_sha256,
    &s2n_ecdhe_rsa_with_3des_ede_cbc_sha,
    &s2n_ecdhe_rsa_with_aes_256_cbc_sha,
    &s2n_rsa_with_aes_128_gcm_sha256,
    &s2n_rsa_with_aes_128_cbc_sha256,
    &s2n_rsa_with_aes_128_cbc_sha,
    &s2n_rsa_with_3des_ede_cbc_sha
};

const struct s2n_cipher_preferences cipher_preferences_20150306 = {
    .count = sizeof(cipher_suites_20150306) / sizeof(cipher_suites_20150306[0]),
    .suites = cipher_suites_20150306,
    .minimum_protocol_version = S2N_TLS10
};

struct s2n_cipher_suite *cipher_suites_20160804[] = {
    &s2n_ecdhe_rsa_with_aes_128_gcm_sha256,
    &s2n_ecdhe_rsa_with_aes_256_gcm_sha384,
    &s2n_ecdhe_rsa_with_aes_128_cbc_sha,
    &s2n_ecdhe_rsa_with_aes_128_cbc_sha256,
    &s2n_ecdhe_rsa_with_aes_256_cbc_sha,
    &s2n_ecdhe_rsa_with_aes_256_cbc_sha384,
    &s2n_rsa_with_aes_128_gcm_sha256,
    &s2n_rsa_with_aes_256_gcm_sha384,
    &s2n_rsa_with_aes_128_cbc_sha,
    &s2n_rsa_with_aes_128_cbc_sha256,
    &s2n_rsa_with_aes_256_cbc_sha,
    &s2n_rsa_with_aes_256_cbc_sha256,
    &s2n_rsa_with_3des_ede_cbc_sha
};

const struct s2n_cipher_preferences cipher_preferences_20160804 = {
    .count = sizeof(cipher_suites_20160804) / sizeof(cipher_suites_20160804[0]),
    .suites = cipher_suites_20160804,
    .minimum_protocol_version = S2N_TLS10
};

struct s2n_cipher_suite *cipher_suites_20160824[] = {
    &s2n_ecdhe_rsa_with_aes_128_gcm_sha256,
    &s2n_ecdhe_rsa_with_aes_256_gcm_sha384,
    &s2n_ecdhe_rsa_with_aes_128_cbc_sha,
    &s2n_ecdhe_rsa_with_aes_128_cbc_sha256,
    &s2n_ecdhe_rsa_with_aes_256_cbc_sha,
    &s2n_rsa_with_aes_128_gcm_sha256,
    &s2n_rsa_with_aes_128_cbc_sha256,
    &s2n_rsa_with_aes_128_cbc_sha
};

const struct s2n_cipher_preferences cipher_preferences_20160824 = {
    .count = sizeof(cipher_suites_20160824) / sizeof(cipher_suites_20160824[0]),
    .suites = cipher_suites_20160824,
    .minimum_protocol_version = S2N_TLS10
};

/* Add ChaCha20 suite */
struct s2n_cipher_suite *cipher_suites_20170210[] = {
    &s2n_ecdhe_rsa_with_aes_128_gcm_sha256,
    &s2n_ecdhe_rsa_with_aes_256_gcm_sha384,
    &s2n_ecdhe_rsa_with_chacha20_poly1305_sha256,
    &s2n_ecdhe_rsa_with_aes_128_cbc_sha,
    &s2n_ecdhe_rsa_with_aes_128_cbc_sha256,
    &s2n_ecdhe_rsa_with_aes_256_cbc_sha,
    &s2n_rsa_with_aes_128_gcm_sha256,
    &s2n_rsa_with_aes_128_cbc_sha256,
    &s2n_rsa_with_aes_128_cbc_sha
};

struct s2n_cipher_suite *cipher_suites_null[] = {
    &s2n_null_cipher_suite
};

const struct s2n_cipher_preferences cipher_preferences_null = {
    .count = sizeof(cipher_suites_null) / sizeof(cipher_suites_null[0]),
    .suites = cipher_suites_null,
    .minimum_protocol_version = S2N_TLS10
};

const struct s2n_cipher_preferences cipher_preferences_20170210 = {
    .count = sizeof(cipher_suites_20170210) / sizeof(cipher_suites_20170210[0]),
    .suites = cipher_suites_20170210,
    .minimum_protocol_version = S2N_TLS10
};

/* Preferences optimized for interop. DHE and 3DES are added(at the lowest preference). */
struct s2n_cipher_suite *cipher_suites_20170328[] = {
    &s2n_ecdhe_rsa_with_aes_128_cbc_sha,
    &s2n_ecdhe_rsa_with_aes_128_gcm_sha256,
    &s2n_ecdhe_rsa_with_aes_256_gcm_sha384,
    &s2n_ecdhe_rsa_with_aes_128_cbc_sha256,
    &s2n_ecdhe_rsa_with_aes_256_cbc_sha,
    &s2n_ecdhe_rsa_with_aes_256_cbc_sha384,
    &s2n_rsa_with_aes_128_cbc_sha,
    &s2n_rsa_with_aes_128_gcm_sha256,
    &s2n_rsa_with_aes_256_gcm_sha384,
    &s2n_rsa_with_aes_128_cbc_sha256,
    &s2n_rsa_with_aes_256_cbc_sha,
    &s2n_rsa_with_aes_256_cbc_sha256,
    &s2n_rsa_with_3des_ede_cbc_sha,
    &s2n_dhe_rsa_with_aes_128_cbc_sha,
    &s2n_dhe_rsa_with_aes_128_gcm_sha256,
    &s2n_dhe_rsa_with_aes_256_gcm_sha384,
    &s2n_dhe_rsa_with_aes_128_cbc_sha256,
    &s2n_dhe_rsa_with_aes_256_cbc_sha,
    &s2n_dhe_rsa_with_aes_256_cbc_sha256,
};

const struct s2n_cipher_preferences cipher_preferences_20170328 = {
    .count = sizeof(cipher_suites_20170328) / sizeof(cipher_suites_20170328[0]),
    .suites = cipher_suites_20170328,
    .minimum_protocol_version = S2N_TLS10
};

/* Preferences optimized for FIPS compatibility. */
struct s2n_cipher_suite *cipher_suites_20170405[] = {
    &s2n_ecdhe_rsa_with_aes_128_cbc_sha256,
    &s2n_ecdhe_rsa_with_aes_256_cbc_sha384,
    &s2n_ecdhe_rsa_with_aes_128_gcm_sha256,
    &s2n_ecdhe_rsa_with_aes_256_gcm_sha384,
    &s2n_rsa_with_aes_128_cbc_sha,
    &s2n_rsa_with_aes_128_gcm_sha256,
    &s2n_rsa_with_aes_256_gcm_sha384,
    &s2n_rsa_with_aes_128_cbc_sha256,
    &s2n_rsa_with_aes_256_cbc_sha,
    &s2n_rsa_with_aes_256_cbc_sha256,
    &s2n_rsa_with_3des_ede_cbc_sha,
};

const struct s2n_cipher_preferences cipher_preferences_20170405 = {
    .count = sizeof(cipher_suites_20170405) / sizeof(cipher_suites_20170405[0]),
    .suites = cipher_suites_20170405,
    .minimum_protocol_version = S2N_TLS10
};

/* Equivalent to cipher_suite_20160411 with 3DES removed.
 * Make a CBC cipher #1 to avoid negotiating GCM with buggy Java clients. */
struct s2n_cipher_suite *cipher_suites_20170718[] = {
    &s2n_ecdhe_rsa_with_aes_128_cbc_sha,
    &s2n_ecdhe_rsa_with_aes_128_gcm_sha256,
    &s2n_ecdhe_rsa_with_aes_256_gcm_sha384,
    &s2n_ecdhe_rsa_with_aes_128_cbc_sha256,
    &s2n_ecdhe_rsa_with_aes_256_cbc_sha,
    &s2n_ecdhe_rsa_with_aes_256_cbc_sha384,
    &s2n_rsa_with_aes_128_cbc_sha,
    &s2n_rsa_with_aes_128_gcm_sha256,
    &s2n_rsa_with_aes_256_gcm_sha384,
    &s2n_rsa_with_aes_128_cbc_sha256,
    &s2n_rsa_with_aes_256_cbc_sha,
    &s2n_rsa_with_aes_256_cbc_sha256,
};

const struct s2n_cipher_preferences cipher_preferences_20170718 = {
    .count = sizeof(cipher_suites_20170718) / sizeof(cipher_suites_20170718[0]),
    .suites = cipher_suites_20170718,
    .minimum_protocol_version = S2N_TLS10
};

struct s2n_cipher_suite *cipher_suites_elb_security_policy_2015_04[] = {
    /* &s2n_ecdhe_ecdsa_with_aes_128_gcm_sha256, */
    &s2n_ecdhe_rsa_with_aes_128_gcm_sha256,
    /* &s2n_ecdhe_ecdsa_with_aes_128_cbc_sha256, */
    &s2n_ecdhe_rsa_with_aes_128_cbc_sha256,
    /* &s2n_ecdhe_ecdsa_with_aes_128_cbc_sha, */
    &s2n_ecdhe_rsa_with_aes_128_cbc_sha,
    /* &s2n_ecdhe_ecdsa_with_aes_256_gcm_sha384, */
    &s2n_ecdhe_rsa_with_aes_256_gcm_sha384,
    /* &s2n_ecdhe_ecdsa_with_aes_256_cbc_sha384, */
    &s2n_ecdhe_rsa_with_aes_256_cbc_sha384,
    &s2n_ecdhe_rsa_with_aes_256_cbc_sha,
    /* &s2n_ecdhe_ecdsa_with_aes_256_cbc_sha, */
    &s2n_rsa_with_aes_128_gcm_sha256,
    &s2n_rsa_with_aes_128_cbc_sha256,
    &s2n_rsa_with_aes_128_cbc_sha,
    &s2n_rsa_with_aes_256_gcm_sha384,
    &s2n_rsa_with_aes_256_cbc_sha256,
    &s2n_rsa_with_aes_256_cbc_sha,
    &s2n_rsa_with_3des_ede_cbc_sha,
};

const struct s2n_cipher_preferences elb_security_policy_2015_04 = {
    .count = sizeof(cipher_suites_elb_security_policy_2015_04) / sizeof(cipher_suites_elb_security_policy_2015_04[0]),
    .suites = cipher_suites_elb_security_policy_2015_04,
    .minimum_protocol_version = S2N_TLS10
};

struct s2n_cipher_suite *cipher_suites_elb_security_policy_2016_08[] = {
    /* &s2n_ecdhe_ecdsa_with_aes_128_gcm_sha256, */
    &s2n_ecdhe_rsa_with_aes_128_gcm_sha256,
    /* &s2n_ecdhe_ecdsa_with_aes_128_cbc_sha256, */
    &s2n_ecdhe_rsa_with_aes_128_cbc_sha256,
    /* &s2n_ecdhe_ecdsa_with_aes_128_cbc_sha, */
    &s2n_ecdhe_rsa_with_aes_128_cbc_sha,
    /* &s2n_ecdhe_ecdsa_with_aes_256_gcm_sha384, */
    &s2n_ecdhe_rsa_with_aes_256_gcm_sha384,
    /* &s2n_ecdhe_ecdsa_with_aes_256_cbc_sha384, */
    &s2n_ecdhe_rsa_with_aes_256_cbc_sha384,
    &s2n_ecdhe_rsa_with_aes_256_cbc_sha,
    /* &s2n_ecdhe_ecdsa_with_aes_256_cbc_sha, */
    &s2n_rsa_with_aes_128_gcm_sha256,
    &s2n_rsa_with_aes_128_cbc_sha256,
    &s2n_rsa_with_aes_128_cbc_sha,
    &s2n_rsa_with_aes_256_gcm_sha384,
    &s2n_rsa_with_aes_256_cbc_sha256,
    &s2n_rsa_with_aes_256_cbc_sha,
};

const struct s2n_cipher_preferences elb_security_policy_2016_08 = {
    .count = sizeof(cipher_suites_elb_security_policy_2016_08) / sizeof(cipher_suites_elb_security_policy_2016_08[0]),
    .suites = cipher_suites_elb_security_policy_2016_08,
    .minimum_protocol_version = S2N_TLS10
};

struct s2n_cipher_suite *cipher_suites_elb_security_policy_tls_1_2_2017_01[] = {
    /* &s2n_ecdhe_ecdsa_with_aes_128_gcm_sha256, */
    &s2n_ecdhe_rsa_with_aes_128_gcm_sha256,
    /* &s2n_ecdhe_ecdsa_with_aes_128_cbc_sha256, */
    &s2n_ecdhe_rsa_with_aes_128_cbc_sha256,
    /* &s2n_ecdhe_ecdsa_with_aes_256_gcm_sha384, */
    &s2n_ecdhe_rsa_with_aes_256_gcm_sha384,
    /* &s2n_ecdhe_ecdsa_with_aes_256_cbc_sha384, */
    &s2n_ecdhe_rsa_with_aes_256_cbc_sha384,
    &s2n_rsa_with_aes_128_gcm_sha256,
    &s2n_rsa_with_aes_128_cbc_sha256,
    &s2n_rsa_with_aes_256_gcm_sha384,
    &s2n_rsa_with_aes_256_cbc_sha256,
};

const struct s2n_cipher_preferences elb_security_policy_tls_1_2_2017_01 = {
    .count = sizeof(cipher_suites_elb_security_policy_tls_1_2_2017_01) / sizeof(cipher_suites_elb_security_policy_tls_1_2_2017_01[0]),
    .suites = cipher_suites_elb_security_policy_tls_1_2_2017_01,
    .minimum_protocol_version = S2N_TLS12
};

struct s2n_cipher_suite *cipher_suites_elb_security_policy_tls_1_1_2017_01[] = {
    /* &s2n_ecdhe_ecdsa_with_aes_128_gcm_sha256, */
    &s2n_ecdhe_rsa_with_aes_128_gcm_sha256,
    /* &s2n_ecdhe_ecdsa_with_aes_128_cbc_sha256, */
    &s2n_ecdhe_rsa_with_aes_128_cbc_sha256,
    /* &s2n_ecdhe_ecdsa_with_aes_128_cbc_sha, */
    &s2n_ecdhe_rsa_with_aes_128_cbc_sha,
    /* &s2n_ecdhe_ecdsa_with_aes_256_gcm_sha384, */
    &s2n_ecdhe_rsa_with_aes_256_gcm_sha384,
    /* &s2n_ecdhe_ecdsa_with_aes_256_cbc_sha384, */
    &s2n_ecdhe_rsa_with_aes_256_cbc_sha384,
    &s2n_ecdhe_rsa_with_aes_256_cbc_sha,
    /* &s2n_ecdhe_ecdsa_with_aes_256_cbc_sha, */
    &s2n_rsa_with_aes_128_gcm_sha256,
    &s2n_rsa_with_aes_128_cbc_sha256,
    &s2n_rsa_with_aes_128_cbc_sha,
    &s2n_rsa_with_aes_256_gcm_sha384,
    &s2n_rsa_with_aes_256_cbc_sha256,
    &s2n_rsa_with_aes_256_cbc_sha,
};

const struct s2n_cipher_preferences elb_security_policy_tls_1_1_2017_01 = {
    .count = sizeof(cipher_suites_elb_security_policy_tls_1_1_2017_01) / sizeof(cipher_suites_elb_security_policy_tls_1_1_2017_01[0]),
    .suites = cipher_suites_elb_security_policy_tls_1_1_2017_01,
    .minimum_protocol_version = S2N_TLS11
};

struct s2n_cipher_suite *cipher_suites_elb_security_policy_tls_1_2_ext_2018_06[] = {
    /* &s2n_ecdhe_ecdsa_with_aes_128_gcm_sha256, */
    &s2n_ecdhe_rsa_with_aes_128_gcm_sha256,
    /* &s2n_ecdhe_ecdsa_with_aes_128_cbc_sha256, */
    &s2n_ecdhe_rsa_with_aes_128_cbc_sha256,
    /* &s2n_ecdhe_ecdsa_with_aes_128_cbc_sha, */
    &s2n_ecdhe_rsa_with_aes_128_cbc_sha,
    /* &s2n_ecdhe_ecdsa_with_aes_256_gcm_sha384, */
    &s2n_ecdhe_rsa_with_aes_256_gcm_sha384,
    /* &s2n_ecdhe_ecdsa_with_aes_256_cbc_sha384, */
    &s2n_ecdhe_rsa_with_aes_256_cbc_sha384,
    &s2n_ecdhe_rsa_with_aes_256_cbc_sha,
    /* &s2n_ecdhe_ecdsa_with_aes_256_cbc_sha, */
    &s2n_rsa_with_aes_128_gcm_sha256,
    &s2n_rsa_with_aes_128_cbc_sha256,
    &s2n_rsa_with_aes_128_cbc_sha,
    &s2n_rsa_with_aes_256_gcm_sha384,
    &s2n_rsa_with_aes_256_cbc_sha256,
    &s2n_rsa_with_aes_256_cbc_sha,
};

const struct s2n_cipher_preferences elb_security_policy_tls_1_2_ext_2018_06 = {
    .count = sizeof(cipher_suites_elb_security_policy_tls_1_2_ext_2018_06) / sizeof(cipher_suites_elb_security_policy_tls_1_2_ext_2018_06[0]),
    .suites = cipher_suites_elb_security_policy_tls_1_2_ext_2018_06,
    .minimum_protocol_version = S2N_TLS12
};

struct s2n_cipher_suite *cipher_suites_elb_security_policy_fs_2018_06[] = {
    /* &s2n_ecdhe_ecdsa_with_aes_128_gcm_sha256, */
    &s2n_ecdhe_rsa_with_aes_128_gcm_sha256,
    /* &s2n_ecdhe_ecdsa_with_aes_128_cbc_sha256, */
    &s2n_ecdhe_rsa_with_aes_128_cbc_sha256,
    /* &s2n_ecdhe_ecdsa_with_aes_128_cbc_sha, */
    &s2n_ecdhe_rsa_with_aes_128_cbc_sha,
    /* &s2n_ecdhe_ecdsa_with_aes_256_gcm_sha384, */
    &s2n_ecdhe_rsa_with_aes_256_gcm_sha384,
    /* &s2n_ecdhe_ecdsa_with_aes_256_cbc_sha384, */
    &s2n_ecdhe_rsa_with_aes_256_cbc_sha384,
    &s2n_ecdhe_rsa_with_aes_256_cbc_sha,
    /* &s2n_ecdhe_ecdsa_with_aes_256_cbc_sha, */
};

const struct s2n_cipher_preferences elb_security_policy_fs_2018_06 = {
    .count = sizeof(cipher_suites_elb_security_policy_fs_2018_06) / sizeof(cipher_suites_elb_security_policy_fs_2018_06[0]),
    .suites = cipher_suites_elb_security_policy_fs_2018_06,
    .minimum_protocol_version = S2N_TLS10
};

struct s2n_cipher_suite *cipher_suites_cloudfront_upstream[] = {
    &s2n_ecdhe_ecdsa_with_aes_256_gcm_sha384,
    &s2n_ecdhe_rsa_with_aes_256_gcm_sha384,
    &s2n_ecdhe_ecdsa_with_aes_128_gcm_sha256,
    &s2n_ecdhe_rsa_with_aes_128_gcm_sha256,
    &s2n_ecdhe_ecdsa_with_aes_256_cbc_sha384,
    &s2n_ecdhe_rsa_with_aes_256_cbc_sha384,
    &s2n_ecdhe_ecdsa_with_aes_256_cbc_sha,
    &s2n_ecdhe_rsa_with_aes_256_cbc_sha,
    &s2n_ecdhe_ecdsa_with_aes_128_cbc_sha256,
    &s2n_ecdhe_rsa_with_aes_128_cbc_sha256,
    &s2n_ecdhe_ecdsa_with_aes_128_cbc_sha,
    &s2n_ecdhe_rsa_with_aes_128_cbc_sha,
    &s2n_rsa_with_aes_256_gcm_sha384,
    &s2n_rsa_with_aes_128_gcm_sha256,
    &s2n_rsa_with_aes_256_cbc_sha,
    &s2n_rsa_with_aes_128_cbc_sha256,
    &s2n_rsa_with_aes_128_cbc_sha,
    &s2n_rsa_with_3des_ede_cbc_sha,
    &s2n_rsa_with_rc4_128_md5
};

const struct s2n_cipher_preferences cipher_preferences_cloudfront_upstream = {
    .count = sizeof(cipher_suites_cloudfront_upstream) / sizeof(cipher_suites_cloudfront_upstream[0]),
    .suites = cipher_suites_cloudfront_upstream,
    .minimum_protocol_version = S2N_SSLv3
};

struct s2n_cipher_suite *cipher_suites_cloudfront_ssl_v_3[] = {
    &s2n_ecdhe_rsa_with_aes_128_gcm_sha256,
    &s2n_ecdhe_rsa_with_aes_128_cbc_sha256,
    &s2n_ecdhe_rsa_with_aes_128_cbc_sha,
    &s2n_ecdhe_rsa_with_aes_256_gcm_sha384,
    &s2n_ecdhe_rsa_with_aes_256_cbc_sha384,
    &s2n_ecdhe_rsa_with_aes_256_cbc_sha,
    &s2n_rsa_with_aes_128_gcm_sha256,
    &s2n_rsa_with_aes_256_gcm_sha384,
    &s2n_rsa_with_aes_128_cbc_sha256,
    &s2n_rsa_with_aes_256_cbc_sha,
    &s2n_rsa_with_aes_128_cbc_sha,
    &s2n_rsa_with_3des_ede_cbc_sha,
    &s2n_rsa_with_rc4_128_md5
};

const struct s2n_cipher_preferences cipher_preferences_cloudfront_ssl_v_3 = {
    .count = sizeof(cipher_suites_cloudfront_ssl_v_3) / sizeof(cipher_suites_cloudfront_ssl_v_3[0]),
    .suites = cipher_suites_cloudfront_ssl_v_3,
    .minimum_protocol_version = S2N_SSLv3
};

struct s2n_cipher_suite *cipher_suites_cloudfront_tls_1_0_2014[] = {
    &s2n_ecdhe_rsa_with_aes_128_gcm_sha256,
    &s2n_ecdhe_rsa_with_aes_128_cbc_sha256,
    &s2n_ecdhe_rsa_with_aes_128_cbc_sha,
    &s2n_ecdhe_rsa_with_aes_256_gcm_sha384,
    &s2n_ecdhe_rsa_with_aes_256_cbc_sha384,
    &s2n_ecdhe_rsa_with_aes_256_cbc_sha,
    &s2n_rsa_with_aes_128_gcm_sha256,
    &s2n_rsa_with_aes_256_gcm_sha384,
    &s2n_rsa_with_aes_128_cbc_sha256,
    &s2n_rsa_with_aes_256_cbc_sha,
    &s2n_rsa_with_aes_128_cbc_sha,
    &s2n_rsa_with_3des_ede_cbc_sha,
};

const struct s2n_cipher_preferences cipher_preferences_cloudfront_tls_1_0_2014 = {
    .count = sizeof(cipher_suites_cloudfront_tls_1_0_2014) / sizeof(cipher_suites_cloudfront_tls_1_0_2014[0]),
    .suites = cipher_suites_cloudfront_tls_1_0_2014,
    .minimum_protocol_version = S2N_TLS10
};

struct s2n_cipher_suite *cipher_suites_cloudfront_tls_1_0_2016[] = {
    &s2n_ecdhe_rsa_with_aes_128_gcm_sha256,
    &s2n_ecdhe_rsa_with_aes_128_cbc_sha256,
    &s2n_ecdhe_rsa_with_aes_128_cbc_sha,
    &s2n_ecdhe_rsa_with_aes_256_gcm_sha384,
    &s2n_ecdhe_rsa_with_aes_256_cbc_sha384,
    &s2n_ecdhe_rsa_with_aes_256_cbc_sha,
    &s2n_rsa_with_aes_128_gcm_sha256,
    &s2n_rsa_with_aes_256_gcm_sha384,
    &s2n_rsa_with_aes_128_cbc_sha256,
    &s2n_rsa_with_aes_256_cbc_sha,
    &s2n_rsa_with_aes_128_cbc_sha
};

const struct s2n_cipher_preferences cipher_preferences_cloudfront_tls_1_0_2016 = {
    .count = sizeof(cipher_suites_cloudfront_tls_1_0_2016) / sizeof(cipher_suites_cloudfront_tls_1_0_2016[0]),
    .suites = cipher_suites_cloudfront_tls_1_0_2016,
    .minimum_protocol_version = S2N_TLS10
};

struct s2n_cipher_suite *cipher_suites_cloudfront_tls_1_1_2016[] = {
    &s2n_ecdhe_rsa_with_aes_128_gcm_sha256,
    &s2n_ecdhe_rsa_with_aes_128_cbc_sha256,
    &s2n_ecdhe_rsa_with_aes_128_cbc_sha,
    &s2n_ecdhe_rsa_with_aes_256_gcm_sha384,
    &s2n_ecdhe_rsa_with_aes_256_cbc_sha384,
    &s2n_ecdhe_rsa_with_aes_256_cbc_sha,
    &s2n_rsa_with_aes_128_gcm_sha256,
    &s2n_rsa_with_aes_256_gcm_sha384,
    &s2n_rsa_with_aes_128_cbc_sha256,
    &s2n_rsa_with_aes_256_cbc_sha,
    &s2n_rsa_with_aes_128_cbc_sha
};

const struct s2n_cipher_preferences cipher_preferences_cloudfront_tls_1_1_2016 = {
    .count = sizeof(cipher_suites_cloudfront_tls_1_1_2016) / sizeof(cipher_suites_cloudfront_tls_1_1_2016[0]),
    .suites = cipher_suites_cloudfront_tls_1_1_2016,
    .minimum_protocol_version = S2N_TLS11
};

struct s2n_cipher_suite *cipher_suites_cloudfront_tls_1_2_2018[] = {
    &s2n_ecdhe_rsa_with_aes_128_gcm_sha256,
    &s2n_ecdhe_rsa_with_aes_128_cbc_sha256,
    &s2n_ecdhe_rsa_with_aes_256_gcm_sha384,
    &s2n_ecdhe_rsa_with_aes_256_cbc_sha384,
    &s2n_rsa_with_aes_128_gcm_sha256,
    &s2n_rsa_with_aes_256_gcm_sha384,
    &s2n_rsa_with_aes_128_cbc_sha256
};

const struct s2n_cipher_preferences cipher_preferences_cloudfront_tls_1_2_2018 = {
    .count = sizeof(cipher_suites_cloudfront_tls_1_2_2018) / sizeof(cipher_suites_cloudfront_tls_1_2_2018[0]),
    .suites = cipher_suites_cloudfront_tls_1_2_2018,
    .minimum_protocol_version = S2N_TLS12
};

struct {
    const char *version;
    const struct s2n_cipher_preferences *preferences;
} selection[] = {
    { "default", &cipher_preferences_20170210 },
    { "default_fips", &cipher_preferences_20170405},
    { "ELBSecurityPolicy-TLS-1-0-2015-04", &elb_security_policy_2015_04},
    /* Not a mistake. TLS-1-0-2015-05 and 2016-08 are equivalent */
    { "ELBSecurityPolicy-TLS-1-0-2015-05", &elb_security_policy_2016_08},
    { "ELBSecurityPolicy-2016-08", &elb_security_policy_2016_08},
    { "ELBSecurityPolicy-TLS-1-1-2017-01", &elb_security_policy_tls_1_1_2017_01},
    { "ELBSecurityPolicy-TLS-1-2-2017-01", &elb_security_policy_tls_1_2_2017_01},
    { "ELBSecurityPolicy-TLS-1-2-Ext-2018-06", &elb_security_policy_tls_1_2_ext_2018_06},
    { "ELBSecurityPolicy-FS-2018-06", &elb_security_policy_fs_2018_06},
    { "CloudFront-Upstream", &cipher_preferences_cloudfront_upstream },
    { "CloudFront-SSL-v-3", &cipher_preferences_cloudfront_ssl_v_3 },
    { "CloudFront-TLS-1-0-2014", &cipher_preferences_cloudfront_tls_1_0_2014 },
    { "CloudFront-TLS-1-0-2016", &cipher_preferences_cloudfront_tls_1_0_2016 },
    { "CloudFront-TLS-1-1-2016", &cipher_preferences_cloudfront_tls_1_1_2016 },
    { "CloudFront-TLS-1-2-2018", &cipher_preferences_cloudfront_tls_1_2_2018 },
    { "20140601", &cipher_preferences_20140601 },
    { "20141001", &cipher_preferences_20141001 },
    { "20150202", &cipher_preferences_20150202 },
    { "20150214", &cipher_preferences_20150214 },
    { "20150306", &cipher_preferences_20150306 },
    { "20160411", &cipher_preferences_20160411 },
    { "20160804", &cipher_preferences_20160804 },
    { "20160824", &cipher_preferences_20160824 },
    { "20170210", &cipher_preferences_20170210 },
    { "20170328", &cipher_preferences_20170328 },
    { "20170405", &cipher_preferences_20170405 },
    { "20170718", &cipher_preferences_20170718 },
    { "test_all", &cipher_preferences_test_all },
    { "test_all_fips", &cipher_preferences_test_all_fips },
    { "test_all_ecdsa", &cipher_preferences_test_all_ecdsa },
    { "null", &cipher_preferences_null },
    { NULL, NULL }
};

int s2n_find_cipher_pref_from_version(const char *version, const struct s2n_cipher_preferences **cipher_preferences)
{
    notnull_check(version);
    notnull_check(cipher_preferences);

    for (int i = 0; selection[i].version != NULL; i++) {
        if (!strcasecmp(version, selection[i].version)) {
            *cipher_preferences = selection[i].preferences;
            return 0;
        }
    }

    S2N_ERROR(S2N_ERR_INVALID_CIPHER_PREFERENCES);
}

int s2n_config_set_cipher_preferences(struct s2n_config *config, const char *version)
{
    GUARD(s2n_find_cipher_pref_from_version(version, &config->cipher_preferences));
    return 0;
}

int s2n_connection_set_cipher_preferences(struct s2n_connection *conn, const char *version)
{
    GUARD(s2n_find_cipher_pref_from_version(version, &conn->cipher_pref_override));
    return 0;
}

int s2n_connection_is_valid_for_cipher_preferences(struct s2n_connection *conn, const char *version)
{
    notnull_check(conn);
    notnull_check(version);
    notnull_check(conn->secure.cipher_suite);

    const struct s2n_cipher_preferences *preferences;
    GUARD(s2n_find_cipher_pref_from_version(version, &preferences));

    /* make sure we dont use a tls version lower than that configured by the version */
    if (s2n_connection_get_actual_protocol_version(conn) < preferences->minimum_protocol_version) {
        return 0;
    }

    struct s2n_cipher_suite *cipher = conn->secure.cipher_suite;
    for (int i = 0; i < preferences->count; ++i) {
        if (0 == memcmp(preferences->suites[i]->iana_value, cipher->iana_value, S2N_TLS_CIPHER_SUITE_LEN)) {
            return 1;
        }
    }

    return 0;
}
