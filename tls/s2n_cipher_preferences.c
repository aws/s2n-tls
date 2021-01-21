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

#include "tls/s2n_cipher_preferences.h"
#include <s2n.h>
#include <stdint.h>
#include <strings.h>
#include "tls/s2n_config.h"
#include "tls/s2n_kem.h"
#include "tls/s2n_kex.h"

#include "error/s2n_errno.h"
#include "utils/s2n_safety.h"

/* clang-format off */
/* TLS 1.3 cipher suites, in order of preference.
 * Can be added to other ciphers suite lists to enable
 * TLS1.3 compatibility. */
#define S2N_TLS13_CIPHER_SUITES_20190801 \
    &s2n_tls13_aes_256_gcm_sha384,       \
    &s2n_tls13_aes_128_gcm_sha256,       \
    &s2n_tls13_chacha20_poly1305_sha256

#define S2N_TLS13_CLOUDFRONT_CIPHER_SUITES_20200716 \
    &s2n_tls13_aes_128_gcm_sha256,       \
    &s2n_tls13_aes_256_gcm_sha384,       \
    &s2n_tls13_chacha20_poly1305_sha256

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
};

/* Disable SSLv3 due to POODLE */
const struct s2n_cipher_preferences cipher_preferences_20141001 = {
    .count = s2n_array_len(cipher_suites_20140601),
    .suites = cipher_suites_20140601,
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
};

struct s2n_cipher_suite *cipher_suites_null[] = {
    &s2n_null_cipher_suite
};

const struct s2n_cipher_preferences cipher_preferences_null = {
    .count = s2n_array_len(cipher_suites_null),
    .suites = cipher_suites_null,
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
};

/* CloudFront viewer facing (with TLS 1.3) */
struct s2n_cipher_suite *cipher_suites_cloudfront_ssl_v_3[] = {
    S2N_TLS13_CLOUDFRONT_CIPHER_SUITES_20200716,
    &s2n_ecdhe_rsa_with_aes_128_gcm_sha256,
    &s2n_ecdhe_rsa_with_aes_128_cbc_sha256,
    &s2n_ecdhe_rsa_with_aes_128_cbc_sha,
    &s2n_ecdhe_rsa_with_aes_256_gcm_sha384,
    &s2n_ecdhe_rsa_with_chacha20_poly1305_sha256,
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
};

struct s2n_cipher_suite *cipher_suites_cloudfront_tls_1_0_2014[] = {
    S2N_TLS13_CLOUDFRONT_CIPHER_SUITES_20200716,
    &s2n_ecdhe_ecdsa_with_aes_128_gcm_sha256,
    &s2n_ecdhe_rsa_with_aes_128_gcm_sha256,
    &s2n_ecdhe_ecdsa_with_aes_128_cbc_sha256,
    &s2n_ecdhe_rsa_with_aes_128_cbc_sha256,
    &s2n_ecdhe_ecdsa_with_aes_128_cbc_sha,
    &s2n_ecdhe_rsa_with_aes_128_cbc_sha,
    &s2n_ecdhe_ecdsa_with_aes_256_gcm_sha384,
    &s2n_ecdhe_rsa_with_aes_256_gcm_sha384,
    &s2n_ecdhe_ecdsa_with_chacha20_poly1305_sha256,
    &s2n_ecdhe_rsa_with_chacha20_poly1305_sha256,
    &s2n_ecdhe_ecdsa_with_aes_256_cbc_sha384,
    &s2n_ecdhe_rsa_with_aes_256_cbc_sha384,
    &s2n_ecdhe_ecdsa_with_aes_256_cbc_sha,
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
};

struct s2n_cipher_suite *cipher_suites_cloudfront_tls_1_0_2016[] = {
    S2N_TLS13_CLOUDFRONT_CIPHER_SUITES_20200716,
    &s2n_ecdhe_ecdsa_with_aes_128_gcm_sha256,
    &s2n_ecdhe_rsa_with_aes_128_gcm_sha256,
    &s2n_ecdhe_ecdsa_with_aes_128_cbc_sha256,
    &s2n_ecdhe_rsa_with_aes_128_cbc_sha256,
    &s2n_ecdhe_ecdsa_with_aes_128_cbc_sha,
    &s2n_ecdhe_rsa_with_aes_128_cbc_sha,
    &s2n_ecdhe_ecdsa_with_aes_256_gcm_sha384,
    &s2n_ecdhe_rsa_with_aes_256_gcm_sha384,
    &s2n_ecdhe_ecdsa_with_chacha20_poly1305_sha256,
    &s2n_ecdhe_rsa_with_chacha20_poly1305_sha256,
    &s2n_ecdhe_ecdsa_with_aes_256_cbc_sha384,
    &s2n_ecdhe_rsa_with_aes_256_cbc_sha384,
    &s2n_ecdhe_ecdsa_with_aes_256_cbc_sha,
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
};

struct s2n_cipher_suite *cipher_suites_cloudfront_tls_1_1_2016[] = {
    S2N_TLS13_CLOUDFRONT_CIPHER_SUITES_20200716,
    &s2n_ecdhe_ecdsa_with_aes_128_gcm_sha256,
    &s2n_ecdhe_rsa_with_aes_128_gcm_sha256,
    &s2n_ecdhe_ecdsa_with_aes_128_cbc_sha256,
    &s2n_ecdhe_rsa_with_aes_128_cbc_sha256,
    &s2n_ecdhe_ecdsa_with_aes_128_cbc_sha,
    &s2n_ecdhe_rsa_with_aes_128_cbc_sha,
    &s2n_ecdhe_ecdsa_with_aes_256_gcm_sha384,
    &s2n_ecdhe_rsa_with_aes_256_gcm_sha384,
    &s2n_ecdhe_ecdsa_with_chacha20_poly1305_sha256,
    &s2n_ecdhe_rsa_with_chacha20_poly1305_sha256,
    &s2n_ecdhe_ecdsa_with_aes_256_cbc_sha384,
    &s2n_ecdhe_rsa_with_aes_256_cbc_sha384,
    &s2n_ecdhe_ecdsa_with_aes_256_cbc_sha,
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
};

struct s2n_cipher_suite *cipher_suites_cloudfront_tls_1_2_2018[] = {
    S2N_TLS13_CLOUDFRONT_CIPHER_SUITES_20200716,
    &s2n_ecdhe_ecdsa_with_aes_128_gcm_sha256,
    &s2n_ecdhe_rsa_with_aes_128_gcm_sha256,
    &s2n_ecdhe_ecdsa_with_aes_128_cbc_sha256,
    &s2n_ecdhe_rsa_with_aes_128_cbc_sha256,
    &s2n_ecdhe_ecdsa_with_aes_256_gcm_sha384,
    &s2n_ecdhe_rsa_with_aes_256_gcm_sha384,
    &s2n_ecdhe_ecdsa_with_chacha20_poly1305_sha256,
    &s2n_ecdhe_rsa_with_chacha20_poly1305_sha256,
    &s2n_ecdhe_ecdsa_with_aes_256_cbc_sha384,
    &s2n_ecdhe_rsa_with_aes_256_cbc_sha384,
    &s2n_rsa_with_aes_128_gcm_sha256,
    &s2n_rsa_with_aes_256_gcm_sha384,
    &s2n_rsa_with_aes_128_cbc_sha256
};

const struct s2n_cipher_preferences cipher_preferences_cloudfront_tls_1_2_2018 = {
    .count = s2n_array_len(cipher_suites_cloudfront_tls_1_2_2018),
    .suites = cipher_suites_cloudfront_tls_1_2_2018,
};

/* CloudFront viewer facing legacy TLS 1.2 policies */
struct s2n_cipher_suite *cipher_suites_cloudfront_ssl_v_3_legacy[] = {
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
    &s2n_ecdhe_ecdsa_with_aes_256_cbc_sha,
    &s2n_ecdhe_rsa_with_aes_256_cbc_sha,
    &s2n_rsa_with_aes_128_gcm_sha256,
    &s2n_rsa_with_aes_256_gcm_sha384,
    &s2n_rsa_with_aes_128_cbc_sha256,
    &s2n_rsa_with_aes_256_cbc_sha,
    &s2n_rsa_with_aes_128_cbc_sha,
    &s2n_rsa_with_3des_ede_cbc_sha,
    &s2n_rsa_with_rc4_128_md5
};

const struct s2n_cipher_preferences cipher_preferences_cloudfront_ssl_v_3_legacy = {
    .count = s2n_array_len(cipher_suites_cloudfront_ssl_v_3_legacy),
    .suites = cipher_suites_cloudfront_ssl_v_3_legacy,
};

struct s2n_cipher_suite *cipher_suites_cloudfront_tls_1_0_2014_legacy[] = {
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
    &s2n_ecdhe_ecdsa_with_aes_256_cbc_sha,
    &s2n_ecdhe_rsa_with_aes_256_cbc_sha,
    &s2n_rsa_with_aes_128_gcm_sha256,
    &s2n_rsa_with_aes_256_gcm_sha384,
    &s2n_rsa_with_aes_128_cbc_sha256,
    &s2n_rsa_with_aes_256_cbc_sha,
    &s2n_rsa_with_aes_128_cbc_sha,
    &s2n_rsa_with_3des_ede_cbc_sha,
};

const struct s2n_cipher_preferences cipher_preferences_cloudfront_tls_1_0_2014_legacy = {
    .count = s2n_array_len(cipher_suites_cloudfront_tls_1_0_2014_legacy),
    .suites = cipher_suites_cloudfront_tls_1_0_2014_legacy,
};

struct s2n_cipher_suite *cipher_suites_cloudfront_tls_1_0_2016_legacy[] = {
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
    &s2n_ecdhe_ecdsa_with_aes_256_cbc_sha,
    &s2n_ecdhe_rsa_with_aes_256_cbc_sha,
    &s2n_rsa_with_aes_128_gcm_sha256,
    &s2n_rsa_with_aes_256_gcm_sha384,
    &s2n_rsa_with_aes_128_cbc_sha256,
    &s2n_rsa_with_aes_256_cbc_sha,
    &s2n_rsa_with_aes_128_cbc_sha
};

const struct s2n_cipher_preferences cipher_preferences_cloudfront_tls_1_0_2016_legacy = {
    .count = s2n_array_len(cipher_suites_cloudfront_tls_1_0_2016_legacy),
    .suites = cipher_suites_cloudfront_tls_1_0_2016_legacy,
};

struct s2n_cipher_suite *cipher_suites_cloudfront_tls_1_1_2016_legacy[] = {
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
    &s2n_ecdhe_ecdsa_with_aes_256_cbc_sha,
    &s2n_ecdhe_rsa_with_aes_256_cbc_sha,
    &s2n_rsa_with_aes_128_gcm_sha256,
    &s2n_rsa_with_aes_256_gcm_sha384,
    &s2n_rsa_with_aes_128_cbc_sha256,
    &s2n_rsa_with_aes_256_cbc_sha,
    &s2n_rsa_with_aes_128_cbc_sha
};

const struct s2n_cipher_preferences cipher_preferences_cloudfront_tls_1_1_2016_legacy = {
    .count = s2n_array_len(cipher_suites_cloudfront_tls_1_1_2016_legacy),
    .suites = cipher_suites_cloudfront_tls_1_1_2016_legacy,
};

struct s2n_cipher_suite *cipher_suites_cloudfront_tls_1_2_2018_legacy[] = {
    &s2n_ecdhe_ecdsa_with_aes_128_gcm_sha256,
    &s2n_ecdhe_rsa_with_aes_128_gcm_sha256,
    &s2n_ecdhe_ecdsa_with_aes_128_cbc_sha256,
    &s2n_ecdhe_rsa_with_aes_128_cbc_sha256,
    &s2n_ecdhe_ecdsa_with_aes_256_gcm_sha384,
    &s2n_ecdhe_rsa_with_aes_256_gcm_sha384,
    &s2n_ecdhe_ecdsa_with_aes_256_cbc_sha384,
    &s2n_ecdhe_rsa_with_aes_256_cbc_sha384,
    &s2n_rsa_with_aes_128_gcm_sha256,
    &s2n_rsa_with_aes_256_gcm_sha384,
    &s2n_rsa_with_aes_128_cbc_sha256
};

const struct s2n_cipher_preferences cipher_preferences_cloudfront_tls_1_2_2018_legacy = {
    .count = s2n_array_len(cipher_suites_cloudfront_tls_1_2_2018_legacy),
    .suites = cipher_suites_cloudfront_tls_1_2_2018_legacy,
};

struct s2n_cipher_suite *cipher_suites_cloudfront_tls_1_2_2019_legacy[] = {
    &s2n_ecdhe_ecdsa_with_aes_128_gcm_sha256,
    &s2n_ecdhe_rsa_with_aes_128_gcm_sha256,
    &s2n_ecdhe_ecdsa_with_aes_256_gcm_sha384,
    &s2n_ecdhe_rsa_with_aes_256_gcm_sha384,
    &s2n_ecdhe_ecdsa_with_aes_256_cbc_sha384,
    &s2n_ecdhe_rsa_with_aes_256_cbc_sha384,
    &s2n_ecdhe_ecdsa_with_aes_128_cbc_sha256,
    &s2n_ecdhe_rsa_with_aes_128_cbc_sha256
};

const struct s2n_cipher_preferences cipher_preferences_cloudfront_tls_1_2_2019_legacy = {
    .count = s2n_array_len(cipher_suites_cloudfront_tls_1_2_2019_legacy),
    .suites = cipher_suites_cloudfront_tls_1_2_2019_legacy,
};

/* CloudFront upstream */
struct s2n_cipher_suite *cipher_suites_cloudfront_upstream_tls10[] = {
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

const struct s2n_cipher_preferences cipher_preferences_cloudfront_upstream_tls10 = {
    .count = s2n_array_len(cipher_suites_cloudfront_upstream_tls10),
    .suites = cipher_suites_cloudfront_upstream_tls10,
};

struct s2n_cipher_suite *cipher_suites_cloudfront_upstream_tls11[] = {
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

const struct s2n_cipher_preferences cipher_preferences_cloudfront_upstream_tls11 = {
    .count = s2n_array_len(cipher_suites_cloudfront_upstream_tls11),
    .suites = cipher_suites_cloudfront_upstream_tls11,
};

struct s2n_cipher_suite *cipher_suites_cloudfront_upstream_tls12[] = {
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

const struct s2n_cipher_preferences cipher_preferences_cloudfront_upstream_tls12 = {
    .count = s2n_array_len(cipher_suites_cloudfront_upstream_tls12),
    .suites = cipher_suites_cloudfront_upstream_tls12,
};

struct s2n_cipher_suite *cipher_suites_cloudfront_tls_1_2_2019[] = {
    S2N_TLS13_CLOUDFRONT_CIPHER_SUITES_20200716,
    &s2n_ecdhe_ecdsa_with_aes_128_gcm_sha256,
    &s2n_ecdhe_rsa_with_aes_128_gcm_sha256,
    &s2n_ecdhe_ecdsa_with_aes_256_gcm_sha384,
    &s2n_ecdhe_rsa_with_aes_256_gcm_sha384,
    &s2n_ecdhe_ecdsa_with_chacha20_poly1305_sha256,
    &s2n_ecdhe_rsa_with_chacha20_poly1305_sha256,
    &s2n_ecdhe_ecdsa_with_aes_256_cbc_sha384,
    &s2n_ecdhe_rsa_with_aes_256_cbc_sha384,
    &s2n_ecdhe_ecdsa_with_aes_128_cbc_sha256,
    &s2n_ecdhe_rsa_with_aes_128_cbc_sha256
};

const struct s2n_cipher_preferences cipher_preferences_cloudfront_tls_1_2_2019 = {
    .count = s2n_array_len(cipher_suites_cloudfront_tls_1_2_2019),
    .suites = cipher_suites_cloudfront_tls_1_2_2019,
};

struct s2n_cipher_suite *cipher_suites_cloudfront_tls_1_2_2021[] = {
    S2N_TLS13_CLOUDFRONT_CIPHER_SUITES_20200716,
    &s2n_ecdhe_ecdsa_with_aes_128_gcm_sha256,
    &s2n_ecdhe_rsa_with_aes_128_gcm_sha256,
    &s2n_ecdhe_ecdsa_with_aes_256_gcm_sha384,
    &s2n_ecdhe_rsa_with_aes_256_gcm_sha384,
    &s2n_ecdhe_ecdsa_with_chacha20_poly1305_sha256,
    &s2n_ecdhe_rsa_with_chacha20_poly1305_sha256
};

const struct s2n_cipher_preferences cipher_preferences_cloudfront_tls_1_2_2021 = {
    .count = s2n_array_len(cipher_suites_cloudfront_tls_1_2_2021),
    .suites = cipher_suites_cloudfront_tls_1_2_2021,
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

/* Includes only round 1 PQ KEM params */
const struct s2n_cipher_preferences cipher_preferences_kms_pq_tls_1_0_2019_06 = {
    .count = s2n_array_len(cipher_suites_kms_pq_tls_1_0_2019_06),
    .suites = cipher_suites_kms_pq_tls_1_0_2019_06,
};

/* Includes round 1 and round 2 PQ KEM params. The cipher suite list is the same
 * as in cipher_preferences_kms_pq_tls_1_0_2019_06.*/
const struct s2n_cipher_preferences cipher_preferences_kms_pq_tls_1_0_2020_02 = {
    .count = s2n_array_len(cipher_suites_kms_pq_tls_1_0_2019_06),
    .suites = cipher_suites_kms_pq_tls_1_0_2019_06,
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

/* Includes only SIKE round 1 (for integration tests) */
const struct s2n_cipher_preferences cipher_preferences_pq_sike_test_tls_1_0_2019_11 = {
    .count = s2n_array_len(cipher_suites_pq_sike_test_tls_1_0_2019_11),
    .suites = cipher_suites_pq_sike_test_tls_1_0_2019_11,
};

/* Includes only SIKE round 1 and round 2 (for integration tests). The cipher suite list
 * is the same as in cipher_preferences_pq_sike_test_tls_1_0_2019_11. */
const struct s2n_cipher_preferences cipher_preferences_pq_sike_test_tls_1_0_2020_02 = {
    .count = s2n_array_len(cipher_suites_pq_sike_test_tls_1_0_2019_11),
    .suites = cipher_suites_pq_sike_test_tls_1_0_2019_11,
};

/* Includes Both Round 2 and Round 1 PQ Ciphers */
struct s2n_cipher_suite *cipher_suites_kms_pq_tls_1_0_2020_07[] = {
    &s2n_ecdhe_kyber_rsa_with_aes_256_gcm_sha384,
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

const struct s2n_cipher_preferences cipher_preferences_kms_pq_tls_1_0_2020_07 = {
    .count = s2n_array_len(cipher_suites_kms_pq_tls_1_0_2020_07),
    .suites = cipher_suites_kms_pq_tls_1_0_2020_07,
};

struct s2n_cipher_suite *cipher_suites_pq_tls_1_0_2020_12[] = {
        S2N_TLS13_CIPHER_SUITES_20190801,
        &s2n_ecdhe_kyber_rsa_with_aes_256_gcm_sha384,
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

const struct s2n_cipher_preferences cipher_preferences_pq_tls_1_0_2020_12 = {
        .count = s2n_array_len(cipher_suites_pq_tls_1_0_2020_12),
        .suites = cipher_suites_pq_tls_1_0_2020_12,
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
};

/* clang-format on */
