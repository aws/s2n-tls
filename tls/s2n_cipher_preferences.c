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
#include "tls/s2n_kex.h"
#include "tls/s2n_config.h"

#include "error/s2n_errno.h"
#include "utils/s2n_safety.h"

/* TLS 1.3 cipher suites, in order of preference.
 * Can be added to other ciphers suite lists to enable
 * TLS1.3 compatibility. */
#define S2N_TLS13_CIPHER_SUITES_20190801    \
    &s2n_tls13_aes_256_gcm_sha384,          \
    &s2n_tls13_aes_128_gcm_sha256,          \
    &s2n_tls13_chacha20_poly1305_sha256     \

/* s2n's list of cipher suites, in order of preferences, as of 2019-08-01 */
struct s2n_cipher_suite *cipher_suites_20190801[] = {
    S2N_TLS13_CIPHER_SUITES_20190801,
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

const struct s2n_cipher_preferences cipher_preferences_20190801 = {
    .count = s2n_array_len(cipher_suites_20190801),
    .suites = cipher_suites_20190801,
    .minimum_protocol_version = S2N_TLS10,
};

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
    .count = s2n_array_len(cipher_suites_20140601),
    .suites = cipher_suites_20140601,
    .minimum_protocol_version = S2N_SSLv3,
};

/* Disable SSLv3 due to POODLE */
const struct s2n_cipher_preferences cipher_preferences_20141001 = {
    .count = s2n_array_len(cipher_suites_20140601),
    .suites = cipher_suites_20140601,
    .minimum_protocol_version = S2N_TLS10,
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
    .count = s2n_array_len(cipher_suites_20150202),
    .suites = cipher_suites_20150202,
    .minimum_protocol_version = S2N_TLS10,
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
    .count = s2n_array_len(cipher_suites_20150214),
    .suites = cipher_suites_20150214,
    .minimum_protocol_version = S2N_TLS10,
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
    .count = s2n_array_len(cipher_suites_20160411),
    .suites = cipher_suites_20160411,
    .minimum_protocol_version = S2N_TLS10,
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
    .count = s2n_array_len(cipher_suites_20150306),
    .suites = cipher_suites_20150306,
    .minimum_protocol_version = S2N_TLS10,
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
    .count = s2n_array_len(cipher_suites_20160804),
    .suites = cipher_suites_20160804,
    .minimum_protocol_version = S2N_TLS10,
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
    .count = s2n_array_len(cipher_suites_20160824),
    .suites = cipher_suites_20160824,
    .minimum_protocol_version = S2N_TLS10,
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

const struct s2n_cipher_preferences cipher_preferences_20170210 = {
    .count = s2n_array_len(cipher_suites_20170210),
    .suites = cipher_suites_20170210,
    .minimum_protocol_version = S2N_TLS10,
};

/* Same as 20160411, but with ChaCha20 added as 1st in Preference List */
struct s2n_cipher_suite *cipher_suites_20190122[] = {
        &s2n_ecdhe_rsa_with_chacha20_poly1305_sha256,
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

const struct s2n_cipher_preferences cipher_preferences_20190122 = {
    .count = s2n_array_len(cipher_suites_20190122),
    .suites = cipher_suites_20190122,
    .minimum_protocol_version = S2N_TLS10,
};

/* Same as 20160804, but with ChaCha20 added as 2nd in Preference List */
struct s2n_cipher_suite *cipher_suites_20190121[] = {
        &s2n_ecdhe_rsa_with_aes_128_gcm_sha256,
        &s2n_ecdhe_rsa_with_aes_256_gcm_sha384,
        &s2n_ecdhe_rsa_with_chacha20_poly1305_sha256,
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

const struct s2n_cipher_preferences cipher_preferences_20190121 = {
    .count = s2n_array_len(cipher_suites_20190121),
    .suites = cipher_suites_20190121,
    .minimum_protocol_version = S2N_TLS10,
};

/* Same as 20160411, but with ChaCha20 in 3rd Place after CBC and GCM */
struct s2n_cipher_suite *cipher_suites_20190120[] = {
        &s2n_ecdhe_rsa_with_aes_128_cbc_sha,
        &s2n_ecdhe_rsa_with_aes_128_gcm_sha256,
        &s2n_ecdhe_rsa_with_aes_256_gcm_sha384,
        &s2n_ecdhe_rsa_with_chacha20_poly1305_sha256,
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

const struct s2n_cipher_preferences cipher_preferences_20190120 = {
    .count = s2n_array_len(cipher_suites_20190120),
    .suites = cipher_suites_20190120,
    .minimum_protocol_version = S2N_TLS10,
};

/* Preferences optimized for interop, includes ECDSA priortitized. DHE and 3DES are added(at the lowest preference). */
struct s2n_cipher_suite *cipher_suites_20190214[] = {
    &s2n_ecdhe_ecdsa_with_aes_128_cbc_sha,
    &s2n_ecdhe_rsa_with_aes_128_cbc_sha,
    &s2n_ecdhe_ecdsa_with_aes_128_gcm_sha256,
    &s2n_ecdhe_rsa_with_aes_128_gcm_sha256,
    &s2n_ecdhe_ecdsa_with_aes_256_gcm_sha384,
    &s2n_ecdhe_rsa_with_aes_256_gcm_sha384,
    &s2n_ecdhe_ecdsa_with_aes_128_cbc_sha256,
    &s2n_ecdhe_rsa_with_aes_128_cbc_sha256,
    &s2n_ecdhe_ecdsa_with_aes_256_cbc_sha,
    &s2n_ecdhe_rsa_with_aes_256_cbc_sha,
    &s2n_ecdhe_ecdsa_with_aes_256_cbc_sha384,
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

const struct s2n_cipher_preferences cipher_preferences_20190214 = {
    .count = s2n_array_len(cipher_suites_20190214),
    .suites = cipher_suites_20190214,
    .minimum_protocol_version = S2N_TLS10,
};

struct s2n_cipher_suite *cipher_suites_null[] = {
    &s2n_null_cipher_suite
};

const struct s2n_cipher_preferences cipher_preferences_null = {
    .count = s2n_array_len(cipher_suites_null),
    .suites = cipher_suites_null,
    .minimum_protocol_version = S2N_TLS10,
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
    .count = s2n_array_len(cipher_suites_20170328),
    .suites = cipher_suites_20170328,
    .minimum_protocol_version = S2N_TLS10,
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
    .count = s2n_array_len(cipher_suites_20170405),
    .suites = cipher_suites_20170405,
    .minimum_protocol_version = S2N_TLS10,
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
    .count = s2n_array_len(cipher_suites_20170718),
    .suites = cipher_suites_20170718,
    .minimum_protocol_version = S2N_TLS10,
};

struct s2n_cipher_suite *cipher_suites_elb_security_policy_2015_04[] = {
    &s2n_ecdhe_ecdsa_with_aes_128_gcm_sha256,
    &s2n_ecdhe_rsa_with_aes_128_gcm_sha256,
    &s2n_ecdhe_ecdsa_with_aes_128_cbc_sha256,
    &s2n_ecdhe_rsa_with_aes_128_cbc_sha256,
    &s2n_ecdhe_ecdsa_with_aes_128_cbc_sha,
    &s2n_ecdhe_rsa_with_aes_128_cbc_sha,
    &s2n_ecdhe_ecdsa_with_aes_256_gcm_sha384,
    &s2n_ecdhe_rsa_with_aes_256_gcm_sha384,
    &s2n_ecdhe_ecdsa_with_aes_256_cbc_sha384,
    &s2n_ecdhe_rsa_with_aes_256_cbc_sha384,
    &s2n_ecdhe_rsa_with_aes_256_cbc_sha,
    &s2n_ecdhe_ecdsa_with_aes_256_cbc_sha,
    &s2n_rsa_with_aes_128_gcm_sha256,
    &s2n_rsa_with_aes_128_cbc_sha256,
    &s2n_rsa_with_aes_128_cbc_sha,
    &s2n_rsa_with_aes_256_gcm_sha384,
    &s2n_rsa_with_aes_256_cbc_sha256,
    &s2n_rsa_with_aes_256_cbc_sha,
    &s2n_rsa_with_3des_ede_cbc_sha,
};

const struct s2n_cipher_preferences elb_security_policy_2015_04 = {
    .count = s2n_array_len(cipher_suites_elb_security_policy_2015_04),
    .suites = cipher_suites_elb_security_policy_2015_04,
    .minimum_protocol_version = S2N_TLS10,
};

struct s2n_cipher_suite *cipher_suites_elb_security_policy_2016_08[] = {
    &s2n_ecdhe_ecdsa_with_aes_128_gcm_sha256,
    &s2n_ecdhe_rsa_with_aes_128_gcm_sha256,
    &s2n_ecdhe_ecdsa_with_aes_128_cbc_sha256,
    &s2n_ecdhe_rsa_with_aes_128_cbc_sha256,
    &s2n_ecdhe_ecdsa_with_aes_128_cbc_sha,
    &s2n_ecdhe_rsa_with_aes_128_cbc_sha,
    &s2n_ecdhe_ecdsa_with_aes_256_gcm_sha384,
    &s2n_ecdhe_rsa_with_aes_256_gcm_sha384,
    &s2n_ecdhe_ecdsa_with_aes_256_cbc_sha384,
    &s2n_ecdhe_rsa_with_aes_256_cbc_sha384,
    &s2n_ecdhe_rsa_with_aes_256_cbc_sha,
    &s2n_ecdhe_ecdsa_with_aes_256_cbc_sha,
    &s2n_rsa_with_aes_128_gcm_sha256,
    &s2n_rsa_with_aes_128_cbc_sha256,
    &s2n_rsa_with_aes_128_cbc_sha,
    &s2n_rsa_with_aes_256_gcm_sha384,
    &s2n_rsa_with_aes_256_cbc_sha256,
    &s2n_rsa_with_aes_256_cbc_sha,
};

const struct s2n_cipher_preferences elb_security_policy_2016_08 = {
    .count = s2n_array_len(cipher_suites_elb_security_policy_2016_08),
    .suites = cipher_suites_elb_security_policy_2016_08,
    .minimum_protocol_version = S2N_TLS10,
};

struct s2n_cipher_suite *cipher_suites_elb_security_policy_tls_1_2_2017_01[] = {
    &s2n_ecdhe_ecdsa_with_aes_128_gcm_sha256,
    &s2n_ecdhe_rsa_with_aes_128_gcm_sha256,
    &s2n_ecdhe_ecdsa_with_aes_128_cbc_sha256,
    &s2n_ecdhe_rsa_with_aes_128_cbc_sha256,
    &s2n_ecdhe_ecdsa_with_aes_256_gcm_sha384,
    &s2n_ecdhe_rsa_with_aes_256_gcm_sha384,
    &s2n_ecdhe_ecdsa_with_aes_256_cbc_sha384,
    &s2n_ecdhe_rsa_with_aes_256_cbc_sha384,
    &s2n_rsa_with_aes_128_gcm_sha256,
    &s2n_rsa_with_aes_128_cbc_sha256,
    &s2n_rsa_with_aes_256_gcm_sha384,
    &s2n_rsa_with_aes_256_cbc_sha256,
};

const struct s2n_cipher_preferences elb_security_policy_tls_1_2_2017_01 = {
    .count = s2n_array_len(cipher_suites_elb_security_policy_tls_1_2_2017_01),
    .suites = cipher_suites_elb_security_policy_tls_1_2_2017_01,
    .minimum_protocol_version = S2N_TLS12,
};

struct s2n_cipher_suite *cipher_suites_elb_security_policy_tls_1_1_2017_01[] = {
    &s2n_ecdhe_ecdsa_with_aes_128_gcm_sha256,
    &s2n_ecdhe_rsa_with_aes_128_gcm_sha256,
    &s2n_ecdhe_ecdsa_with_aes_128_cbc_sha256,
    &s2n_ecdhe_rsa_with_aes_128_cbc_sha256,
    &s2n_ecdhe_ecdsa_with_aes_128_cbc_sha,
    &s2n_ecdhe_rsa_with_aes_128_cbc_sha,
    &s2n_ecdhe_ecdsa_with_aes_256_gcm_sha384,
    &s2n_ecdhe_rsa_with_aes_256_gcm_sha384,
    &s2n_ecdhe_ecdsa_with_aes_256_cbc_sha384,
    &s2n_ecdhe_rsa_with_aes_256_cbc_sha384,
    &s2n_ecdhe_rsa_with_aes_256_cbc_sha,
    &s2n_ecdhe_ecdsa_with_aes_256_cbc_sha,
    &s2n_rsa_with_aes_128_gcm_sha256,
    &s2n_rsa_with_aes_128_cbc_sha256,
    &s2n_rsa_with_aes_128_cbc_sha,
    &s2n_rsa_with_aes_256_gcm_sha384,
    &s2n_rsa_with_aes_256_cbc_sha256,
    &s2n_rsa_with_aes_256_cbc_sha,
};

const struct s2n_cipher_preferences elb_security_policy_tls_1_1_2017_01 = {
    .count = s2n_array_len(cipher_suites_elb_security_policy_tls_1_1_2017_01),
    .suites = cipher_suites_elb_security_policy_tls_1_1_2017_01,
    .minimum_protocol_version = S2N_TLS11,
};

struct s2n_cipher_suite *cipher_suites_elb_security_policy_tls_1_2_ext_2018_06[] = {
    &s2n_ecdhe_ecdsa_with_aes_128_gcm_sha256,
    &s2n_ecdhe_rsa_with_aes_128_gcm_sha256,
    &s2n_ecdhe_ecdsa_with_aes_128_cbc_sha256,
    &s2n_ecdhe_rsa_with_aes_128_cbc_sha256,
    &s2n_ecdhe_ecdsa_with_aes_128_cbc_sha,
    &s2n_ecdhe_rsa_with_aes_128_cbc_sha,
    &s2n_ecdhe_ecdsa_with_aes_256_gcm_sha384,
    &s2n_ecdhe_rsa_with_aes_256_gcm_sha384,
    &s2n_ecdhe_ecdsa_with_aes_256_cbc_sha384,
    &s2n_ecdhe_rsa_with_aes_256_cbc_sha384,
    &s2n_ecdhe_rsa_with_aes_256_cbc_sha,
    &s2n_ecdhe_ecdsa_with_aes_256_cbc_sha,
    &s2n_rsa_with_aes_128_gcm_sha256,
    &s2n_rsa_with_aes_128_cbc_sha256,
    &s2n_rsa_with_aes_128_cbc_sha,
    &s2n_rsa_with_aes_256_gcm_sha384,
    &s2n_rsa_with_aes_256_cbc_sha256,
    &s2n_rsa_with_aes_256_cbc_sha,
};

const struct s2n_cipher_preferences elb_security_policy_tls_1_2_ext_2018_06 = {
    .count = s2n_array_len(cipher_suites_elb_security_policy_tls_1_2_ext_2018_06),
    .suites = cipher_suites_elb_security_policy_tls_1_2_ext_2018_06,
    .minimum_protocol_version = S2N_TLS12,
};

struct s2n_cipher_suite *cipher_suites_elb_security_policy_fs_2018_06[] = {
    &s2n_ecdhe_ecdsa_with_aes_128_gcm_sha256,
    &s2n_ecdhe_rsa_with_aes_128_gcm_sha256,
    &s2n_ecdhe_ecdsa_with_aes_128_cbc_sha256,
    &s2n_ecdhe_rsa_with_aes_128_cbc_sha256,
    &s2n_ecdhe_ecdsa_with_aes_128_cbc_sha,
    &s2n_ecdhe_rsa_with_aes_128_cbc_sha,
    &s2n_ecdhe_ecdsa_with_aes_256_gcm_sha384,
    &s2n_ecdhe_rsa_with_aes_256_gcm_sha384,
    &s2n_ecdhe_ecdsa_with_aes_256_cbc_sha384,
    &s2n_ecdhe_rsa_with_aes_256_cbc_sha384,
    &s2n_ecdhe_rsa_with_aes_256_cbc_sha,
    &s2n_ecdhe_ecdsa_with_aes_256_cbc_sha,
};

const struct s2n_cipher_preferences elb_security_policy_fs_2018_06 = {
    .count = s2n_array_len(cipher_suites_elb_security_policy_fs_2018_06),
    .suites = cipher_suites_elb_security_policy_fs_2018_06,
    .minimum_protocol_version = S2N_TLS10,
};

struct s2n_cipher_suite *cipher_suites_elb_security_policy_fs_1_2_2019_08[] = {
    &s2n_ecdhe_ecdsa_with_aes_128_gcm_sha256,
    &s2n_ecdhe_rsa_with_aes_128_gcm_sha256,
    &s2n_ecdhe_ecdsa_with_aes_128_cbc_sha256,
    &s2n_ecdhe_rsa_with_aes_128_cbc_sha256,
    &s2n_ecdhe_ecdsa_with_aes_128_cbc_sha,
    &s2n_ecdhe_rsa_with_aes_128_cbc_sha,
    &s2n_ecdhe_ecdsa_with_aes_256_gcm_sha384,
    &s2n_ecdhe_rsa_with_aes_256_gcm_sha384,
    &s2n_ecdhe_ecdsa_with_aes_256_cbc_sha384,
    &s2n_ecdhe_rsa_with_aes_256_cbc_sha384,
    &s2n_ecdhe_rsa_with_aes_256_cbc_sha,
    &s2n_ecdhe_ecdsa_with_aes_256_cbc_sha,
};

const struct s2n_cipher_preferences elb_security_policy_fs_1_2_2019_08 = {
    .count = s2n_array_len(cipher_suites_elb_security_policy_fs_1_2_2019_08),
    .suites = cipher_suites_elb_security_policy_fs_1_2_2019_08, 
    .minimum_protocol_version = S2N_TLS12,
};

struct s2n_cipher_suite *cipher_suites_elb_security_policy_fs_1_1_2019_08[] = {
    &s2n_ecdhe_ecdsa_with_aes_128_gcm_sha256,
    &s2n_ecdhe_rsa_with_aes_128_gcm_sha256,
    &s2n_ecdhe_ecdsa_with_aes_128_cbc_sha256,
    &s2n_ecdhe_rsa_with_aes_128_cbc_sha256,
    &s2n_ecdhe_ecdsa_with_aes_128_cbc_sha,
    &s2n_ecdhe_rsa_with_aes_128_cbc_sha,
    &s2n_ecdhe_ecdsa_with_aes_256_gcm_sha384,
    &s2n_ecdhe_rsa_with_aes_256_gcm_sha384,
    &s2n_ecdhe_ecdsa_with_aes_256_cbc_sha384,
    &s2n_ecdhe_rsa_with_aes_256_cbc_sha384,
    &s2n_ecdhe_rsa_with_aes_256_cbc_sha,
    &s2n_ecdhe_ecdsa_with_aes_256_cbc_sha,
};

const struct s2n_cipher_preferences elb_security_policy_fs_1_1_2019_08 = {
    .count = s2n_array_len(cipher_suites_elb_security_policy_fs_1_1_2019_08),
    .suites = cipher_suites_elb_security_policy_fs_1_1_2019_08, 
    .minimum_protocol_version = S2N_TLS11,
};

struct s2n_cipher_suite *cipher_suites_elb_security_policy_fs_1_2_Res_2019_08[] = {
    &s2n_ecdhe_ecdsa_with_aes_128_gcm_sha256,
    &s2n_ecdhe_rsa_with_aes_128_gcm_sha256,
    &s2n_ecdhe_ecdsa_with_aes_128_cbc_sha256,
    &s2n_ecdhe_rsa_with_aes_128_cbc_sha256,
    &s2n_ecdhe_ecdsa_with_aes_256_gcm_sha384,
    &s2n_ecdhe_rsa_with_aes_256_gcm_sha384,
    &s2n_ecdhe_ecdsa_with_aes_256_cbc_sha384,
    &s2n_ecdhe_rsa_with_aes_256_cbc_sha384,
};

const struct s2n_cipher_preferences elb_security_policy_fs_1_2_Res_2019_08 = {
    .count = s2n_array_len(cipher_suites_elb_security_policy_fs_1_2_Res_2019_08),
    .suites = cipher_suites_elb_security_policy_fs_1_2_Res_2019_08, 
    .minimum_protocol_version = S2N_TLS12,
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
    .count = s2n_array_len(cipher_suites_cloudfront_upstream),
    .suites = cipher_suites_cloudfront_upstream,
    .minimum_protocol_version = S2N_SSLv3,
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
    .count = s2n_array_len(cipher_suites_cloudfront_ssl_v_3),
    .suites = cipher_suites_cloudfront_ssl_v_3,
    .minimum_protocol_version = S2N_SSLv3,
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
    .count = s2n_array_len(cipher_suites_cloudfront_tls_1_0_2014),
    .suites = cipher_suites_cloudfront_tls_1_0_2014,
    .minimum_protocol_version = S2N_TLS10,
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
    .count = s2n_array_len(cipher_suites_cloudfront_tls_1_0_2016),
    .suites = cipher_suites_cloudfront_tls_1_0_2016,
    .minimum_protocol_version = S2N_TLS10,
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
    .count = s2n_array_len(cipher_suites_cloudfront_tls_1_1_2016),
    .suites = cipher_suites_cloudfront_tls_1_1_2016,
    .minimum_protocol_version = S2N_TLS11,
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
    .count = s2n_array_len(cipher_suites_cloudfront_tls_1_2_2018),
    .suites = cipher_suites_cloudfront_tls_1_2_2018,
    .minimum_protocol_version = S2N_TLS12,
};

struct s2n_cipher_suite *cipher_suites_cloudfront_tls_1_2_2019[] = {
    &s2n_ecdhe_rsa_with_aes_128_gcm_sha256,
    &s2n_ecdhe_rsa_with_aes_256_gcm_sha384,
    &s2n_rsa_with_aes_128_gcm_sha256,
    &s2n_rsa_with_aes_256_gcm_sha384
};

const struct s2n_cipher_preferences cipher_preferences_cloudfront_tls_1_2_2019 = {
    .count = s2n_array_len(cipher_suites_cloudfront_tls_1_2_2019),
    .suites = cipher_suites_cloudfront_tls_1_2_2019,
    .minimum_protocol_version = S2N_TLS12,
};

struct s2n_cipher_suite *cipher_suites_kms_tls_1_0_2018_10[] = {
        &s2n_ecdhe_rsa_with_aes_256_gcm_sha384,
        &s2n_ecdhe_rsa_with_aes_128_gcm_sha256,
        &s2n_ecdhe_rsa_with_aes_256_cbc_sha384,
        &s2n_ecdhe_rsa_with_aes_256_cbc_sha,
        &s2n_ecdhe_rsa_with_aes_128_cbc_sha256,
        &s2n_ecdhe_rsa_with_3des_ede_cbc_sha,
        &s2n_dhe_rsa_with_aes_256_cbc_sha256,
        &s2n_dhe_rsa_with_aes_128_cbc_sha256,
        &s2n_dhe_rsa_with_aes_256_cbc_sha,
        &s2n_dhe_rsa_with_aes_128_cbc_sha,
};

const struct s2n_cipher_preferences cipher_preferences_kms_tls_1_0_2018_10 = {
        .count = s2n_array_len(cipher_suites_kms_tls_1_0_2018_10),
        .suites = cipher_suites_kms_tls_1_0_2018_10,
        .minimum_protocol_version = S2N_TLS10,
};

struct s2n_cipher_suite *cipher_suites_kms_pq_tls_1_0_2019_06[] = {
        &s2n_ecdhe_bike_rsa_with_aes_256_gcm_sha384,
        &s2n_ecdhe_sike_rsa_with_aes_256_gcm_sha384,
        &s2n_ecdhe_rsa_with_aes_256_gcm_sha384,
        &s2n_ecdhe_rsa_with_aes_128_gcm_sha256,
        &s2n_ecdhe_rsa_with_aes_256_cbc_sha384,
        &s2n_ecdhe_rsa_with_aes_256_cbc_sha,
        &s2n_ecdhe_rsa_with_aes_128_cbc_sha256,
        &s2n_ecdhe_rsa_with_3des_ede_cbc_sha,
        &s2n_dhe_rsa_with_aes_256_cbc_sha256,
        &s2n_dhe_rsa_with_aes_128_cbc_sha256,
        &s2n_dhe_rsa_with_aes_256_cbc_sha,
        &s2n_dhe_rsa_with_aes_128_cbc_sha,
};

const struct s2n_cipher_preferences cipher_preferences_kms_pq_tls_1_0_2019_06 = {
        .count = s2n_array_len(cipher_suites_kms_pq_tls_1_0_2019_06),
        .suites = cipher_suites_kms_pq_tls_1_0_2019_06,
        .minimum_protocol_version = S2N_TLS10,
};

struct s2n_cipher_suite *cipher_suites_pq_sike_test_tls_1_0_2019_11[] = {
        &s2n_ecdhe_sike_rsa_with_aes_256_gcm_sha384,
        &s2n_ecdhe_rsa_with_aes_256_gcm_sha384,
        &s2n_ecdhe_rsa_with_aes_128_gcm_sha256,
        &s2n_ecdhe_rsa_with_aes_256_cbc_sha384,
        &s2n_ecdhe_rsa_with_aes_256_cbc_sha,
        &s2n_ecdhe_rsa_with_aes_128_cbc_sha256,
        &s2n_ecdhe_rsa_with_3des_ede_cbc_sha,
        &s2n_dhe_rsa_with_aes_256_cbc_sha256,
        &s2n_dhe_rsa_with_aes_128_cbc_sha256,
        &s2n_dhe_rsa_with_aes_256_cbc_sha,
        &s2n_dhe_rsa_with_aes_128_cbc_sha,
};

const struct s2n_cipher_preferences cipher_preferences_pq_sike_test_tls_1_0_2019_11 = {
        .count = s2n_array_len(cipher_suites_pq_sike_test_tls_1_0_2019_11),
        .suites = cipher_suites_pq_sike_test_tls_1_0_2019_11,
        .minimum_protocol_version = S2N_TLS10,
};

struct s2n_cipher_suite *cipher_suites_kms_fips_tls_1_2_2018_10[] = {
        &s2n_ecdhe_rsa_with_aes_256_gcm_sha384,
        &s2n_ecdhe_rsa_with_aes_128_gcm_sha256,
        &s2n_ecdhe_rsa_with_aes_256_cbc_sha384,
        &s2n_ecdhe_rsa_with_aes_128_cbc_sha256,
        &s2n_dhe_rsa_with_aes_256_cbc_sha256,
        &s2n_dhe_rsa_with_aes_128_cbc_sha256,
};

const struct s2n_cipher_preferences cipher_preferences_kms_fips_tls_1_2_2018_10 = {
        .count = s2n_array_len(cipher_suites_kms_fips_tls_1_2_2018_10),
        .suites = cipher_suites_kms_fips_tls_1_2_2018_10,
        .minimum_protocol_version = S2N_TLS12,

};

struct {
    const char *version;
    const struct s2n_cipher_preferences *preferences;
    unsigned ecc_extension_required:1;
    unsigned pq_kem_extension_required:1;
} selection[] = {
    /* Zero init .ecc_extension_required and .pq_kem_extension_required, they'll be initialized later in s2n_cipher_preferences_init() */
    { .version="default", .preferences=&cipher_preferences_20170210, .ecc_extension_required=0, .pq_kem_extension_required=0},
    { .version="default_tls13", .preferences=&cipher_preferences_20190801, .ecc_extension_required=0, .pq_kem_extension_required=0},
    { .version="default_fips", .preferences=&cipher_preferences_20170405, .ecc_extension_required=0, .pq_kem_extension_required=0},
    { .version="ELBSecurityPolicy-TLS-1-0-2015-04", .preferences=&elb_security_policy_2015_04, .ecc_extension_required=0, .pq_kem_extension_required=0},
    /* Not a mistake. TLS-1-0-2015-05 and 2016-08 are equivalent */
    { .version="ELBSecurityPolicy-TLS-1-0-2015-05", .preferences=&elb_security_policy_2016_08, .ecc_extension_required=0, .pq_kem_extension_required=0},
    { .version="ELBSecurityPolicy-2016-08", .preferences=&elb_security_policy_2016_08, .ecc_extension_required=0, .pq_kem_extension_required=0},
    { .version="ELBSecurityPolicy-TLS-1-1-2017-01", .preferences=&elb_security_policy_tls_1_1_2017_01, .ecc_extension_required=0, .pq_kem_extension_required=0},
    { .version="ELBSecurityPolicy-TLS-1-2-2017-01", .preferences=&elb_security_policy_tls_1_2_2017_01, .ecc_extension_required=0, .pq_kem_extension_required=0},
    { .version="ELBSecurityPolicy-TLS-1-2-Ext-2018-06", .preferences=&elb_security_policy_tls_1_2_ext_2018_06, .ecc_extension_required=0, .pq_kem_extension_required=0},
    { .version="ELBSecurityPolicy-FS-2018-06", .preferences=&elb_security_policy_fs_2018_06, .ecc_extension_required=0, .pq_kem_extension_required=0},
    { .version="ELBSecurityPolicy-FS-1-2-2019-08", .preferences=&elb_security_policy_fs_1_2_2019_08, .ecc_extension_required=0, .pq_kem_extension_required=0}, 
    { .version="ELBSecurityPolicy-FS-1-1-2019-08", .preferences=&elb_security_policy_fs_1_1_2019_08, .ecc_extension_required=0, .pq_kem_extension_required=0}, 
    { .version="ELBSecurityPolicy-FS-1-2-Res-2019-08", .preferences=&elb_security_policy_fs_1_2_Res_2019_08, .ecc_extension_required=0, .pq_kem_extension_required=0}, 
    { .version="CloudFront-Upstream", .preferences=&cipher_preferences_cloudfront_upstream, .ecc_extension_required=0, .pq_kem_extension_required=0},
    { .version="CloudFront-SSL-v-3", .preferences=&cipher_preferences_cloudfront_ssl_v_3, .ecc_extension_required=0, .pq_kem_extension_required=0},
    { .version="CloudFront-TLS-1-0-2014", .preferences=&cipher_preferences_cloudfront_tls_1_0_2014, .ecc_extension_required=0, .pq_kem_extension_required=0},
    { .version="CloudFront-TLS-1-0-2016", .preferences=&cipher_preferences_cloudfront_tls_1_0_2016, .ecc_extension_required=0, .pq_kem_extension_required=0},
    { .version="CloudFront-TLS-1-1-2016", .preferences=&cipher_preferences_cloudfront_tls_1_1_2016, .ecc_extension_required=0, .pq_kem_extension_required=0},
    { .version="CloudFront-TLS-1-2-2018", .preferences=&cipher_preferences_cloudfront_tls_1_2_2018, .ecc_extension_required=0, .pq_kem_extension_required=0},
    { .version="CloudFront-TLS-1-2-2019", .preferences=&cipher_preferences_cloudfront_tls_1_2_2019, .ecc_extension_required=0, .pq_kem_extension_required=0},
    { .version="KMS-TLS-1-0-2018-10", .preferences=&cipher_preferences_kms_tls_1_0_2018_10, .ecc_extension_required=0, .pq_kem_extension_required=0},
    { .version="KMS-PQ-TLS-1-0-2019-06", .preferences=&cipher_preferences_kms_pq_tls_1_0_2019_06, .ecc_extension_required=0, .pq_kem_extension_required=0},
    { .version="PQ-SIKE-TEST-TLS-1-0-2019-11", .preferences=&cipher_preferences_pq_sike_test_tls_1_0_2019_11, .ecc_extension_required=0, .pq_kem_extension_required=0},
    { .version="KMS-FIPS-TLS-1-2-2018-10", .preferences=&cipher_preferences_kms_fips_tls_1_2_2018_10, .ecc_extension_required=0, .pq_kem_extension_required=0},
    { .version="20140601", .preferences=&cipher_preferences_20140601, .ecc_extension_required=0, .pq_kem_extension_required=0},
    { .version="20141001", .preferences=&cipher_preferences_20141001, .ecc_extension_required=0, .pq_kem_extension_required=0},
    { .version="20150202", .preferences=&cipher_preferences_20150202, .ecc_extension_required=0, .pq_kem_extension_required=0},
    { .version="20150214", .preferences=&cipher_preferences_20150214, .ecc_extension_required=0, .pq_kem_extension_required=0},
    { .version="20150306", .preferences=&cipher_preferences_20150306, .ecc_extension_required=0, .pq_kem_extension_required=0},
    { .version="20160411", .preferences=&cipher_preferences_20160411, .ecc_extension_required=0, .pq_kem_extension_required=0},
    { .version="20160804", .preferences=&cipher_preferences_20160804, .ecc_extension_required=0, .pq_kem_extension_required=0},
    { .version="20160824", .preferences=&cipher_preferences_20160824, .ecc_extension_required=0, .pq_kem_extension_required=0},
    { .version="20170210", .preferences=&cipher_preferences_20170210, .ecc_extension_required=0, .pq_kem_extension_required=0},
    { .version="20170328", .preferences=&cipher_preferences_20170328, .ecc_extension_required=0, .pq_kem_extension_required=0},
    { .version="20190214", .preferences=&cipher_preferences_20190214, .ecc_extension_required=0, .pq_kem_extension_required=0},
    { .version="20170405", .preferences=&cipher_preferences_20170405, .ecc_extension_required=0, .pq_kem_extension_required=0},
    { .version="20170718", .preferences=&cipher_preferences_20170718, .ecc_extension_required=0, .pq_kem_extension_required=0},
    { .version="20190120", .preferences=&cipher_preferences_20190120, .ecc_extension_required=0, .pq_kem_extension_required=0},
    { .version="20190121", .preferences=&cipher_preferences_20190121, .ecc_extension_required=0, .pq_kem_extension_required=0},
    { .version="20190122", .preferences=&cipher_preferences_20190122, .ecc_extension_required=0, .pq_kem_extension_required=0},
    { .version="test_all", .preferences=&cipher_preferences_test_all, .ecc_extension_required=0, .pq_kem_extension_required=0},
    { .version="test_all_fips", .preferences=&cipher_preferences_test_all_fips, .ecc_extension_required=0, .pq_kem_extension_required=0},
    { .version="test_all_ecdsa", .preferences=&cipher_preferences_test_all_ecdsa, .ecc_extension_required=0, .pq_kem_extension_required=0},
    { .version="test_ecdsa_priority", .preferences=&cipher_preferences_test_ecdsa_priority, .ecc_extension_required=0, .pq_kem_extension_required=0},
    { .version="test_tls13_null_key_exchange_alg", .preferences=&cipher_preferences_test_tls13_null_key_exchange_alg, .ecc_extension_required=0, .pq_kem_extension_required=0},
    { .version="null", .preferences=&cipher_preferences_null, .ecc_extension_required=0, .pq_kem_extension_required=0},
    { .version=NULL, .preferences=NULL, .ecc_extension_required=0, .pq_kem_extension_required=0}
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

int s2n_cipher_preferences_init()
{
    for (int i = 0; selection[i].version != NULL; i++) {
        const struct s2n_cipher_preferences *preferences = selection[i].preferences;
        for (int j = 0; j < preferences->count; j++) {

            struct s2n_cipher_suite *cipher = preferences->suites[j];

            /* TLS1.3 does not include key exchange algorithms in its cipher suites,
             * but the elliptic curves extension is always required. */
            if (cipher->minimum_required_tls_version >= S2N_TLS13) {
                selection[i].ecc_extension_required = 1;
            }

            if (cipher->key_exchange_alg == &s2n_ecdhe || cipher->key_exchange_alg == &s2n_hybrid_ecdhe_kem) {
                selection[i].ecc_extension_required = 1;
            }

            if (cipher->key_exchange_alg == &s2n_hybrid_ecdhe_kem) {
                selection[i].pq_kem_extension_required = 1;
            }
        }
    }
    return 0;
}

int s2n_ecc_extension_required(const struct s2n_cipher_preferences *preferences)
{
    notnull_check(preferences);
    for (int i = 0; selection[i].version != NULL; i++) {
        if (selection[i].preferences == preferences) {
            return 1 == selection[i].ecc_extension_required;
        }
    }
    S2N_ERROR(S2N_ERR_INVALID_CIPHER_PREFERENCES);
}

int s2n_pq_kem_extension_required(const struct s2n_cipher_preferences *preferences)
{
    notnull_check(preferences);
    for (int i = 0; selection[i].version != NULL; i++) {
        if (selection[i].preferences == preferences) {
            return 1 == selection[i].pq_kem_extension_required;
        }
    }
    S2N_ERROR(S2N_ERR_INVALID_CIPHER_PREFERENCES);
}
