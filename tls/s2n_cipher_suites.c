/*
 * Copyright 2014 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

#include <string.h>

#include "error/s2n_errno.h"

#include "crypto/s2n_cipher.h"

#include "tls/s2n_cipher_preferences.h"
#include "tls/s2n_cipher_suites.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_tls.h"
#include "utils/s2n_safety.h"

const struct s2n_key_exchange_algorithm s2n_rsa = {
    .flags = 0,
};

const struct s2n_key_exchange_algorithm s2n_dhe = {
    .flags = S2N_KEY_EXCHANGE_DH | S2N_KEY_EXCHANGE_EPH,
};

const struct s2n_key_exchange_algorithm s2n_ecdhe = {
    .flags = S2N_KEY_EXCHANGE_DH | S2N_KEY_EXCHANGE_EPH | S2N_KEY_EXCHANGE_ECC,
};

const struct s2n_record_algorithm s2n_record_alg_null = {
    .cipher = &s2n_null_cipher,
    .hmac_alg = S2N_HMAC_NONE,
    .flags = 0,
};

const struct s2n_record_algorithm s2n_record_alg_rc4_md5 = {
    .cipher = &s2n_rc4,
    .hmac_alg = S2N_HMAC_MD5,
    .flags = 0,
};

const struct s2n_record_algorithm s2n_record_alg_rc4_sha = {
    .cipher = &s2n_rc4,
    .hmac_alg = S2N_HMAC_SHA1,
    .flags = 0,
};

const struct s2n_record_algorithm s2n_record_alg_3des_sha = {
    .cipher = &s2n_3des,
    .hmac_alg = S2N_HMAC_SHA1,
    .flags = 0,
};

const struct s2n_record_algorithm s2n_record_alg_aes128_sha = {
    .cipher = &s2n_aes128,
    .hmac_alg = S2N_HMAC_SHA1,
    .flags = 0,
};

const struct s2n_record_algorithm s2n_record_alg_aes128_sha_composite = {
    .cipher = &s2n_aes128_sha,
    .hmac_alg = S2N_HMAC_NONE,
    .flags = 0,
};

const struct s2n_record_algorithm s2n_record_alg_aes128_sha256 = {
    .cipher = &s2n_aes128,
    .hmac_alg = S2N_HMAC_SHA256,
    .flags = 0,
};

const struct s2n_record_algorithm s2n_record_alg_aes128_sha256_composite = {
    .cipher = &s2n_aes128_sha256,
    .hmac_alg = S2N_HMAC_NONE,
};

const struct s2n_record_algorithm s2n_record_alg_aes256_sha = {
    .cipher = &s2n_aes256,
    .hmac_alg = S2N_HMAC_SHA1,
    .flags = 0,
};

const struct s2n_record_algorithm s2n_record_alg_aes256_sha_composite = {
    .cipher = &s2n_aes256_sha,
    .hmac_alg = S2N_HMAC_NONE,
    .flags = 0,
};

const struct s2n_record_algorithm s2n_record_alg_aes256_sha256 = {
    .cipher = &s2n_aes256,
    .hmac_alg = S2N_HMAC_SHA256,
    .flags = 0,
};

const struct s2n_record_algorithm s2n_record_alg_aes256_sha256_composite = {
    .cipher = &s2n_aes256_sha256,
    .hmac_alg = S2N_HMAC_NONE,
};

const struct s2n_record_algorithm s2n_record_alg_aes256_sha384 = {
    .cipher = &s2n_aes256,
    .hmac_alg = S2N_HMAC_SHA384,
    .flags = 0,
};

const struct s2n_record_algorithm s2n_record_alg_aes128_gcm = {
    .cipher = &s2n_aes128_gcm,
    .hmac_alg = S2N_HMAC_NONE,
    .flags = S2N_TLS12_AES_GCM_AEAD_NONCE,
};

const struct s2n_record_algorithm s2n_record_alg_aes256_gcm = {
    .cipher = &s2n_aes256_gcm,
    .hmac_alg = S2N_HMAC_NONE,
    .flags = S2N_TLS12_AES_GCM_AEAD_NONCE,
};

const struct s2n_record_algorithm s2n_record_alg_chacha20_poly1305 = {
    .cipher = &s2n_chacha20_poly1305,
    .hmac_alg = S2N_HMAC_NONE,
    /* Per RFC 7905, ChaCha20-Poly1305 will use a nonce construction expected to be used in TLS1.3.
     * Give it a distinct 1.2 nonce value in case this changes.
     */
    .flags = S2N_TLS12_CHACHA_POLY_AEAD_NONCE,
};

/* This is the initial cipher suite, but is never negotiated */
struct s2n_cipher_suite s2n_null_cipher_suite = {
    .available = 1,
    .name = "TLS_NULL_WITH_NULL_NULL",
    .iana_value = { TLS_NULL_WITH_NULL_NULL },
    .key_exchange_alg = &s2n_rsa,
    .record_alg = &s2n_record_alg_null,
};

struct s2n_cipher_suite s2n_rsa_with_rc4_128_md5 = /* 0x00,0x04 */ {
    .available = 0,
    .name = "RC4-MD5",
    .iana_value = { TLS_RSA_WITH_RC4_128_MD5 },
    .key_exchange_alg = &s2n_rsa,
    .record_alg = NULL,
    .all_record_algs = { &s2n_record_alg_rc4_md5 },
    .num_record_algs = 1,
    .tls12_prf_alg = S2N_HMAC_SHA256,
    .minimum_required_tls_version = S2N_SSLv3,
};

struct s2n_cipher_suite s2n_rsa_with_rc4_128_sha = /* 0x00,0x05 */ {
    .available = 0,
    .name = "RC4-SHA",
    .iana_value = { TLS_RSA_WITH_RC4_128_SHA },
    .key_exchange_alg = &s2n_rsa,
    .record_alg = NULL,
    .all_record_algs = { &s2n_record_alg_rc4_sha },
    .num_record_algs = 1,
    .tls12_prf_alg = S2N_HMAC_SHA256,
    .minimum_required_tls_version = S2N_SSLv3,
};

struct s2n_cipher_suite s2n_rsa_with_3des_ede_cbc_sha = /* 0x00,0x0A */ {
    .available = 0,
    .name = "DES-CBC3-SHA",
    .iana_value = { TLS_RSA_WITH_3DES_EDE_CBC_SHA },
    .key_exchange_alg = &s2n_rsa,
    .record_alg = NULL,
    .all_record_algs = { &s2n_record_alg_3des_sha },
    .num_record_algs = 1,
    .tls12_prf_alg = S2N_HMAC_SHA256,
    .minimum_required_tls_version = S2N_SSLv3,
};

struct s2n_cipher_suite s2n_dhe_rsa_with_3des_ede_cbc_sha = /* 0x00,0x16 */ {
    .available = 0,
    .name = "EDH-RSA-DES-CBC3-SHA",
    .iana_value = { TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA },
    .key_exchange_alg = &s2n_dhe,
    .record_alg = NULL,
    .all_record_algs = { &s2n_record_alg_3des_sha },
    .num_record_algs = 1,
    .tls12_prf_alg = S2N_HMAC_SHA256,
    .minimum_required_tls_version = S2N_SSLv3,
};

struct s2n_cipher_suite s2n_rsa_with_aes_128_cbc_sha = /* 0x00,0x2F */ {
    .available = 0,
    .name = "AES128-SHA",
    .iana_value = { TLS_RSA_WITH_AES_128_CBC_SHA },
    .key_exchange_alg = &s2n_rsa,
    .record_alg = NULL,
    .all_record_algs = { &s2n_record_alg_aes128_sha_composite, &s2n_record_alg_aes128_sha },
    .num_record_algs = 2,
    .tls12_prf_alg = S2N_HMAC_SHA256,
    .minimum_required_tls_version = S2N_SSLv3,
};

struct s2n_cipher_suite s2n_dhe_rsa_with_aes_128_cbc_sha = /* 0x00,0x33 */ {
    .available = 0,
    .name = "DHE-RSA-AES128-SHA",
    .iana_value = { TLS_DHE_RSA_WITH_AES_128_CBC_SHA },
    .key_exchange_alg = &s2n_dhe,
    .record_alg = NULL,
    .all_record_algs = { &s2n_record_alg_aes128_sha_composite, &s2n_record_alg_aes128_sha },
    .num_record_algs = 2,
    .tls12_prf_alg = S2N_HMAC_SHA256,
    .minimum_required_tls_version = S2N_SSLv3,
};

struct s2n_cipher_suite s2n_rsa_with_aes_256_cbc_sha = /* 0x00,0x35 */ {
    .available = 0,
    .name = "AES256-SHA",
    .iana_value = { TLS_RSA_WITH_AES_256_CBC_SHA },
    .key_exchange_alg = &s2n_rsa,
    .record_alg = NULL,
    .all_record_algs = { &s2n_record_alg_aes256_sha_composite , &s2n_record_alg_aes256_sha },
    .num_record_algs = 2,
    .tls12_prf_alg = S2N_HMAC_SHA256,
    .minimum_required_tls_version = S2N_SSLv3,
};

struct s2n_cipher_suite s2n_dhe_rsa_with_aes_256_cbc_sha = /* 0x00,0x39 */ {
    .available = 0,
    .name = "DHE-RSA-AES256-SHA",
    .iana_value = { TLS_DHE_RSA_WITH_AES_256_CBC_SHA },
    .key_exchange_alg = &s2n_dhe,
    .record_alg = NULL,
    .all_record_algs = { &s2n_record_alg_aes256_sha_composite , &s2n_record_alg_aes256_sha },
    .num_record_algs = 2,
    .tls12_prf_alg = S2N_HMAC_SHA256,
    .minimum_required_tls_version = S2N_SSLv3,
};

struct s2n_cipher_suite s2n_rsa_with_aes_128_cbc_sha256 = /* 0x00,0x3C */ {
    .available = 0,
    .name = "AES128-SHA256",
    .iana_value = { TLS_RSA_WITH_AES_128_CBC_SHA256 },
    .key_exchange_alg = &s2n_rsa,
    .record_alg = NULL,
    .all_record_algs = { &s2n_record_alg_aes128_sha256_composite, &s2n_record_alg_aes128_sha256 },
    .num_record_algs = 2,
    .tls12_prf_alg = S2N_HMAC_SHA256,
    .minimum_required_tls_version = S2N_TLS12,
};

struct s2n_cipher_suite s2n_rsa_with_aes_256_cbc_sha256 = /* 0x00,0x3D */ {
    .available = 0,
    .name = "AES256-SHA256",
    .iana_value = { TLS_RSA_WITH_AES_256_CBC_SHA256 },
    .key_exchange_alg = &s2n_rsa,
    .record_alg = NULL,
    .all_record_algs = { &s2n_record_alg_aes256_sha256_composite, &s2n_record_alg_aes256_sha256 },
    .num_record_algs = 2,
    .tls12_prf_alg = S2N_HMAC_SHA256,
    .minimum_required_tls_version = S2N_TLS12,
};

struct s2n_cipher_suite s2n_dhe_rsa_with_aes_128_cbc_sha256 = /* 0x00,0x67 */ {
    .available = 0,
    .name = "DHE-RSA-AES128-SHA256",
    .iana_value = { TLS_DHE_RSA_WITH_AES_128_CBC_SHA256 },
    .key_exchange_alg = &s2n_dhe,
    .record_alg = NULL,
    .all_record_algs = { &s2n_record_alg_aes128_sha256_composite, &s2n_record_alg_aes128_sha256 },
    .num_record_algs = 2,
    .tls12_prf_alg = S2N_HMAC_SHA256,
    .minimum_required_tls_version = S2N_TLS12,
};

struct s2n_cipher_suite s2n_dhe_rsa_with_aes_256_cbc_sha256 = /* 0x00,0x6B */ {
    .available = 0,
    .name = "DHE-RSA-AES256-SHA256",
    .iana_value = { TLS_DHE_RSA_WITH_AES_256_CBC_SHA256 },
    .key_exchange_alg = &s2n_dhe,
    .record_alg = NULL,
    .all_record_algs = { &s2n_record_alg_aes256_sha256_composite, &s2n_record_alg_aes256_sha256 },
    .num_record_algs = 2,
    .tls12_prf_alg = S2N_HMAC_SHA256,
    .minimum_required_tls_version = S2N_TLS12,
};

struct s2n_cipher_suite s2n_rsa_with_aes_128_gcm_sha256 = /* 0x00,0x9C */ {
    .available = 0,
    .name = "AES128-GCM-SHA256",
    .iana_value = { TLS_RSA_WITH_AES_128_GCM_SHA256 },
    .key_exchange_alg = &s2n_rsa,
    .record_alg = NULL,
    .all_record_algs = { &s2n_record_alg_aes128_gcm },
    .num_record_algs = 1,
    .tls12_prf_alg = S2N_HMAC_SHA256,
    .minimum_required_tls_version = S2N_TLS12,
};

struct s2n_cipher_suite s2n_rsa_with_aes_256_gcm_sha384 = /* 0x00,0x9D */ {
    .available = 0,
    .name = "AES256-GCM-SHA384",
    .iana_value = { TLS_RSA_WITH_AES_256_GCM_SHA384 },
    .key_exchange_alg = &s2n_rsa,
    .record_alg = NULL,
    .all_record_algs = { &s2n_record_alg_aes256_gcm },
    .num_record_algs = 1,
    .tls12_prf_alg = S2N_HMAC_SHA384,
    .minimum_required_tls_version = S2N_TLS12,
};

struct s2n_cipher_suite s2n_dhe_rsa_with_aes_128_gcm_sha256 = /* 0x00,0x9E */ {
    .available = 0,
    .name = "DHE-RSA-AES128-GCM-SHA256",
    .iana_value = { TLS_DHE_RSA_WITH_AES_128_GCM_SHA256 },
    .key_exchange_alg = &s2n_dhe,
    .record_alg = NULL,
    .all_record_algs = { &s2n_record_alg_aes128_gcm },
    .num_record_algs = 1,
    .tls12_prf_alg = S2N_HMAC_SHA256,
    .minimum_required_tls_version = S2N_TLS12,
};

struct s2n_cipher_suite s2n_dhe_rsa_with_aes_256_gcm_sha384 = /* 0x00,0x9F */ {
    .available = 0,
    .name = "DHE-RSA-AES256-GCM-SHA384",
    .iana_value = { TLS_DHE_RSA_WITH_AES_256_GCM_SHA384 },
    .key_exchange_alg = &s2n_dhe,
    .record_alg = NULL,
    .all_record_algs = { &s2n_record_alg_aes256_gcm },
    .num_record_algs = 1,
    .tls12_prf_alg = S2N_HMAC_SHA384,
    .minimum_required_tls_version = S2N_TLS12,
};

struct s2n_cipher_suite s2n_ecdhe_rsa_with_3des_ede_cbc_sha = /* 0xC0,0x12 */ {
    .available = 0,
    .name = "ECDHE-RSA-DES-CBC3-SHA",
    .iana_value = { TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA },
    .key_exchange_alg = &s2n_ecdhe,
    .record_alg = NULL,
    .all_record_algs = { &s2n_record_alg_3des_sha },
    .num_record_algs = 1,
    .tls12_prf_alg = S2N_HMAC_SHA256,
    .minimum_required_tls_version = S2N_TLS10,
};

struct s2n_cipher_suite s2n_ecdhe_rsa_with_aes_128_cbc_sha = /* 0xC0,0x13 */ {
    .available = 0,
    .name = "ECDHE-RSA-AES128-SHA",
    .iana_value = { TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA },
    .key_exchange_alg = &s2n_ecdhe,
    .record_alg = NULL,
    .all_record_algs = { &s2n_record_alg_aes128_sha_composite, &s2n_record_alg_aes128_sha },
    .num_record_algs = 2,
    .tls12_prf_alg = S2N_HMAC_SHA256,
    .minimum_required_tls_version = S2N_TLS10,
};

struct s2n_cipher_suite s2n_ecdhe_rsa_with_aes_256_cbc_sha = /* 0xC0,0x14 */ {
    .available = 0,
    .name = "ECDHE-RSA-AES256-SHA",
    .iana_value = { TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA },
    .key_exchange_alg = &s2n_ecdhe,
    .record_alg = NULL,
    .all_record_algs = { &s2n_record_alg_aes256_sha_composite , &s2n_record_alg_aes256_sha },
    .num_record_algs = 2,
    .tls12_prf_alg = S2N_HMAC_SHA256,
    .minimum_required_tls_version = S2N_TLS10,
};

struct s2n_cipher_suite s2n_ecdhe_rsa_with_aes_128_cbc_sha256 = /* 0xC0,0x27 */ {
    .available = 0,
    .name = "ECDHE-RSA-AES128-SHA256",
    .iana_value = { TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 },
    .key_exchange_alg = &s2n_ecdhe,
    .record_alg = NULL,
    .all_record_algs = { &s2n_record_alg_aes128_sha256_composite, &s2n_record_alg_aes128_sha256 },
    .num_record_algs = 2,
    .tls12_prf_alg = S2N_HMAC_SHA256,
    .minimum_required_tls_version = S2N_TLS12,
};

struct s2n_cipher_suite s2n_ecdhe_rsa_with_aes_256_cbc_sha384 = /* 0xC0,0x28 */ {
    .available = 0,
    .name = "ECDHE-RSA-AES256-SHA384",
    .iana_value = { TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384 },
    .key_exchange_alg = &s2n_ecdhe,
    .record_alg = NULL,
    .all_record_algs = { &s2n_record_alg_aes256_sha384 },
    .num_record_algs = 1,
    .tls12_prf_alg = S2N_HMAC_SHA384,
    .minimum_required_tls_version = S2N_TLS12,
};

struct s2n_cipher_suite s2n_ecdhe_rsa_with_aes_128_gcm_sha256 = /* 0xC0,0x2F */ {
    .available = 0,
    .name = "ECDHE-RSA-AES128-GCM-SHA256",
    .iana_value = { TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 },
    .key_exchange_alg = &s2n_ecdhe,
    .record_alg = NULL,
    .all_record_algs = { &s2n_record_alg_aes128_gcm },
    .num_record_algs = 1,
    .tls12_prf_alg = S2N_HMAC_SHA256,
    .minimum_required_tls_version = S2N_TLS12,
};

struct s2n_cipher_suite s2n_ecdhe_rsa_with_aes_256_gcm_sha384 = /* 0xC0,0x30 */ {
    .available = 0,
    .name = "ECDHE-RSA-AES256-GCM-SHA384",
    .iana_value = { TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 },
    .key_exchange_alg = &s2n_ecdhe,
    .record_alg = NULL,
    .all_record_algs = { &s2n_record_alg_aes256_gcm },
    .num_record_algs = 1,
    .tls12_prf_alg = S2N_HMAC_SHA384,
    .minimum_required_tls_version = S2N_TLS12,
};

struct s2n_cipher_suite s2n_ecdhe_rsa_with_chacha20_poly1305_sha256 = /* 0xCC,0xA8 */ {
    .available = 0,
    .name = "ECDHE-RSA-CHACHA20-POLY1305",
    .iana_value = { TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 },
    .key_exchange_alg = &s2n_ecdhe,
    .record_alg = NULL,
    .all_record_algs = { &s2n_record_alg_chacha20_poly1305 },
    .num_record_algs = 1,
    .tls12_prf_alg = S2N_HMAC_SHA256,
    .minimum_required_tls_version = S2N_TLS12,
};

struct s2n_cipher_suite s2n_dhe_rsa_with_chacha20_poly1305_sha256 = /* 0xCC,0xAA */ {
    .available = 0,
    .name = "DHE-RSA-CHACHA20-POLY1305",
    .iana_value = { TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256 },
    .key_exchange_alg = &s2n_dhe,
    .record_alg = NULL,
    .all_record_algs = { &s2n_record_alg_chacha20_poly1305 },
    .num_record_algs = 1,
    .tls12_prf_alg = S2N_HMAC_SHA256,
    .minimum_required_tls_version = S2N_TLS12,
};

/* All of the cipher suites that s2n negotiates, in order of IANA value.
 * Exposed for the "test_all" cipher preference list.
 */
static struct s2n_cipher_suite *s2n_all_cipher_suites[] = {
    &s2n_rsa_with_rc4_128_md5,                     /* 0x00,0x04 */
    &s2n_rsa_with_rc4_128_sha,                     /* 0x00,0x05 */
    &s2n_rsa_with_3des_ede_cbc_sha,                /* 0x00,0x0A */
    &s2n_dhe_rsa_with_3des_ede_cbc_sha,            /* 0x00,0x16 */
    &s2n_rsa_with_aes_128_cbc_sha,                 /* 0x00,0x2F */
    &s2n_dhe_rsa_with_aes_128_cbc_sha,             /* 0x00,0x33 */
    &s2n_rsa_with_aes_256_cbc_sha,                 /* 0x00,0x35 */
    &s2n_dhe_rsa_with_aes_256_cbc_sha,             /* 0x00,0x39 */
    &s2n_rsa_with_aes_128_cbc_sha256,              /* 0x00,0x3C */
    &s2n_rsa_with_aes_256_cbc_sha256,              /* 0x00,0x3D */
    &s2n_dhe_rsa_with_aes_128_cbc_sha256,          /* 0x00,0x67 */
    &s2n_dhe_rsa_with_aes_256_cbc_sha256,          /* 0x00,0x6B */
    &s2n_rsa_with_aes_128_gcm_sha256,              /* 0x00,0x9C */
    &s2n_rsa_with_aes_256_gcm_sha384,              /* 0x00,0x9D */
    &s2n_dhe_rsa_with_aes_128_gcm_sha256,          /* 0x00,0x9E */
    &s2n_dhe_rsa_with_aes_256_gcm_sha384,          /* 0x00,0x9F */
    &s2n_ecdhe_rsa_with_3des_ede_cbc_sha,          /* 0xC0,0x12 */
    &s2n_ecdhe_rsa_with_aes_128_cbc_sha,           /* 0xC0,0x13 */
    &s2n_ecdhe_rsa_with_aes_256_cbc_sha,           /* 0xC0,0x14 */
    &s2n_ecdhe_rsa_with_aes_128_cbc_sha256,        /* 0xC0,0x27 */
    &s2n_ecdhe_rsa_with_aes_256_cbc_sha384,        /* 0xC0,0x28 */
    &s2n_ecdhe_rsa_with_aes_128_gcm_sha256,        /* 0xC0,0x2F */
    &s2n_ecdhe_rsa_with_aes_256_gcm_sha384,        /* 0xC0,0x30 */
    &s2n_ecdhe_rsa_with_chacha20_poly1305_sha256,  /* 0xCC,0xA8 */
    &s2n_dhe_rsa_with_chacha20_poly1305_sha256,    /* 0xCC,0xAA */
};

/* All supported ciphers. Exposed for integration testing. */
const struct s2n_cipher_preferences cipher_preferences_test_all = {
    .count = sizeof(s2n_all_cipher_suites) / sizeof(s2n_all_cipher_suites[0]),
    .suites = s2n_all_cipher_suites,
    .minimum_protocol_version = S2N_SSLv3
};

/* Determines cipher suite availability and selects record algorithms */
int s2n_cipher_suites_init(void)
{
    const int num_cipher_suites = sizeof(s2n_all_cipher_suites) / sizeof(s2n_all_cipher_suites[0]);
    for (int i = 0; i < num_cipher_suites; i++) {
        struct s2n_cipher_suite *cur_suite = s2n_all_cipher_suites[i];
        cur_suite->available = 0;
        cur_suite->record_alg = NULL;

        /* Find the highest priority supported record algorithm */
        for (int j = 0; j < cur_suite->num_record_algs; j++) {
            /* Can we use the record algorithm's cipher? Won't be available if the system CPU architecture
             * doesn't support it or if the libcrypto lacks the feature. All hmac_algs are supported.
             */
            if (cur_suite->all_record_algs[j]->cipher->is_available()) {
                /* Found a supported record algorithm. Use it. */
                cur_suite->available = 1;
                cur_suite->record_alg = cur_suite->all_record_algs[j];
                break;
            }
        }
    }

    return 0;
}

/* Reset any selected record algorithms */
int s2n_cipher_suites_cleanup(void)
{
    const int num_cipher_suites = sizeof(s2n_all_cipher_suites) / sizeof(struct s2n_cipher_suite*);
    for (int i = 0; i < num_cipher_suites; i++) {
        struct s2n_cipher_suite *cur_suite = s2n_all_cipher_suites[i];
        cur_suite->available = 0;
        cur_suite->record_alg = NULL;
    }

    return 0;
}

struct s2n_cipher_suite *s2n_cipher_suite_from_wire(const uint8_t cipher_suite[S2N_TLS_CIPHER_SUITE_LEN])
{
    int low = 0;
    int top = (sizeof(s2n_all_cipher_suites) / sizeof(struct s2n_cipher_suite*)) - 1;

    /* Perform a textbook binary search */
    while (low <= top) {
        /* Check in the middle */
        int mid = low + ((top - low) / 2);
        int m = memcmp(s2n_all_cipher_suites[mid]->iana_value, cipher_suite, 2);

        if (m == 0) {
            return s2n_all_cipher_suites[mid];
        } else if (m > 0) {
            top = mid - 1;
        } else if (m < 0) {
            low = mid + 1;
        }
    }

    return NULL;
}

int s2n_set_cipher_as_client(struct s2n_connection *conn, uint8_t wire[S2N_TLS_CIPHER_SUITE_LEN])
{
    /* See if the cipher is one we support */
    conn->secure.cipher_suite = s2n_cipher_suite_from_wire(wire);
    if (conn->secure.cipher_suite == NULL) {
        S2N_ERROR(S2N_ERR_CIPHER_NOT_SUPPORTED);
    }

    return 0;
}

static int s2n_wire_ciphers_contain(const uint8_t * match, const uint8_t * wire, uint32_t count, uint32_t cipher_suite_len)
{
    for (int i = 0; i < count; i++) {
        const uint8_t *theirs = wire + (i * cipher_suite_len) + (cipher_suite_len - S2N_TLS_CIPHER_SUITE_LEN);

        if (!memcmp(match, theirs, S2N_TLS_CIPHER_SUITE_LEN)) {
            return 1;
        }
    }

    return 0;
}

static int s2n_set_cipher_as_server(struct s2n_connection *conn, uint8_t * wire, uint32_t count, uint32_t cipher_suite_len)
{
    uint8_t renegotiation_info_scsv[S2N_TLS_CIPHER_SUITE_LEN] = { TLS_EMPTY_RENEGOTIATION_INFO_SCSV };
    struct s2n_cipher_suite *higher_vers_match = NULL;

    /* RFC 7507 - If client is attempting to negotiate a TLS Version that is lower than the highest supported server
     * version, and the client cipher list contains TLS_FALLBACK_SCSV, then the server must abort the connection since
     * TLS_FALLBACK_SCSV should only be present when the client previously failed to negotiate a higher TLS version.
     */
    if (conn->client_protocol_version < s2n_highest_protocol_version) {
        uint8_t fallback_scsv[S2N_TLS_CIPHER_SUITE_LEN] = { TLS_FALLBACK_SCSV };
        if (s2n_wire_ciphers_contain(fallback_scsv, wire, count, cipher_suite_len)) {
            conn->closed = 1;
            S2N_ERROR(S2N_ERR_FALLBACK_DETECTED);
        }
    }

    /* RFC5746 Section 3.6: A server must check if TLS_EMPTY_RENEGOTIATION_INFO_SCSV is included */
    if (s2n_wire_ciphers_contain(renegotiation_info_scsv, wire, count, cipher_suite_len)) {
        conn->secure_renegotiation = 1;
    }

    /* s2n supports only server order */
    for (int i = 0; i < conn->config->cipher_preferences->count; i++) {
        const uint8_t *ours = conn->config->cipher_preferences->suites[i]->iana_value;

        if (s2n_wire_ciphers_contain(ours, wire, count, cipher_suite_len)) {
            /* We have a match */
            struct s2n_cipher_suite *match = s2n_cipher_suite_from_wire(ours);

            /* Skip the suite if we don't have an available implementation */
            if (!match->available) {
                continue;
            }

            /* Don't choose DHE key exchange if it's not configured. */
            if (conn->config->dhparams == NULL && match->key_exchange_alg == &s2n_dhe) {
                continue;
            }
            /* Don't choose EC ciphers if the curve was not agreed upon. */
            if (conn->secure.server_ecc_params.negotiated_curve == NULL && (match->key_exchange_alg->flags & S2N_KEY_EXCHANGE_ECC)) {
                continue;
            }

            /* Don't immediately choose a cipher the client shouldn't be able to support */
            if (conn->client_protocol_version < match->minimum_required_tls_version) {
                higher_vers_match = match;
                continue;
            }

            conn->secure.cipher_suite = match;
            return 0;
        }
    }

    /* Settle for a cipher with a higher required proto version, if it was set */
    if (higher_vers_match != NULL) {
        conn->secure.cipher_suite = higher_vers_match;
        return 0;
    }

    S2N_ERROR(S2N_ERR_CIPHER_NOT_SUPPORTED);
}

int s2n_set_cipher_as_sslv2_server(struct s2n_connection *conn, uint8_t * wire, uint16_t count)
{
    return s2n_set_cipher_as_server(conn, wire, count, S2N_SSLv2_CIPHER_SUITE_LEN);
}

int s2n_set_cipher_as_tls_server(struct s2n_connection *conn, uint8_t * wire, uint16_t count)
{
    return s2n_set_cipher_as_server(conn, wire, count, S2N_TLS_CIPHER_SUITE_LEN);
}
