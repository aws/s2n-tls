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

#pragma once

#include "tls/s2n_tls_parameters.h"
#include "tls/s2n_connection.h"

#include "crypto/s2n_cipher.h"
#include "crypto/s2n_hmac.h"

#include <stdint.h>

/* Key exchange flags that can be OR'ed */
#define S2N_KEY_EXCHANGE_DH       0x01  /* Diffie-Hellman key exchange, including ephemeral */
#define S2N_KEY_EXCHANGE_EPH      0x02  /* Ephemeral key exchange */
#define S2N_KEY_EXCHANGE_ECC      0x04  /* Elliptic curve cryptography */

struct s2n_key_exchange_algorithm {
    /* OR'ed S2N_KEY_EXCHANGE_* flags */
    uint16_t flags;
};

extern const struct s2n_key_exchange_algorithm s2n_rsa;
extern const struct s2n_key_exchange_algorithm s2n_dhe;
extern const struct s2n_key_exchange_algorithm s2n_ecdhe;

#define S2N_MAX_POSSIBLE_RECORD_ALGS  2

/* Record algorithm flags that can be OR'ed */
#define S2N_TLS12_AES_GCM_AEAD_NONCE     0x01
#define S2N_TLS12_CHACHA_POLY_AEAD_NONCE 0x02

struct s2n_record_algorithm {
    const struct s2n_cipher *cipher;
    s2n_hmac_algorithm hmac_alg;
    uint32_t flags;
};

/* Verbose names to avoid confusion with s2n_cipher. Exposed for unit tests */
extern const struct s2n_record_algorithm s2n_record_alg_null;
extern const struct s2n_record_algorithm s2n_record_alg_rc4_md5;
extern const struct s2n_record_algorithm s2n_record_alg_rc4_sha;
extern const struct s2n_record_algorithm s2n_record_alg_3des_sha;
extern const struct s2n_record_algorithm s2n_record_alg_aes128_sha;
extern const struct s2n_record_algorithm s2n_record_alg_aes128_sha_composite;
extern const struct s2n_record_algorithm s2n_record_alg_aes128_sha256;
extern const struct s2n_record_algorithm s2n_record_alg_aes128_sha256_composite;
extern const struct s2n_record_algorithm s2n_record_alg_aes256_sha;
extern const struct s2n_record_algorithm s2n_record_alg_aes256_sha_composite;
extern const struct s2n_record_algorithm s2n_record_alg_aes256_sha256;
extern const struct s2n_record_algorithm s2n_record_alg_aes256_sha256_composite;
extern const struct s2n_record_algorithm s2n_record_alg_aes256_sha384;
extern const struct s2n_record_algorithm s2n_record_alg_aes128_gcm;
extern const struct s2n_record_algorithm s2n_record_alg_aes256_gcm;
extern const struct s2n_record_algorithm s2n_record_alg_chacha20_poly1305;

struct s2n_cipher_suite {
    /* Is there an implementation available? Set in s2n_cipher_suites_init() */
    unsigned int available:1;

    /* Cipher name in Openssl format */
    const char *name;
    const uint8_t iana_value[2];

    const struct s2n_key_exchange_algorithm *key_exchange_alg;

    /* Algorithms used for per-record security. Set in s2n_cipher_suites_init() */
    const struct s2n_record_algorithm *record_alg;

    /* List of all possible record alg implementations in descending priority */
    const struct s2n_record_algorithm *all_record_algs[S2N_MAX_POSSIBLE_RECORD_ALGS];
    const uint8_t num_record_algs;

    /* RFC 5426(TLS1.2) allows cipher suite defined PRFs. Cipher suites defined in and before TLS1.2 will use
     * P_hash with SHA256 when TLS1.2 is negotiated.
     */
    const s2n_hmac_algorithm tls12_prf_alg;

    const uint8_t minimum_required_tls_version;
};

/* Never negotiated */
extern struct s2n_cipher_suite s2n_null_cipher_suite;

extern struct s2n_cipher_suite s2n_rsa_with_rc4_128_md5;
extern struct s2n_cipher_suite s2n_rsa_with_rc4_128_sha;
extern struct s2n_cipher_suite s2n_rsa_with_3des_ede_cbc_sha;
extern struct s2n_cipher_suite s2n_dhe_rsa_with_3des_ede_cbc_sha;
extern struct s2n_cipher_suite s2n_rsa_with_aes_128_cbc_sha;
extern struct s2n_cipher_suite s2n_dhe_rsa_with_aes_128_cbc_sha;
extern struct s2n_cipher_suite s2n_rsa_with_aes_256_cbc_sha;
extern struct s2n_cipher_suite s2n_dhe_rsa_with_aes_256_cbc_sha;
extern struct s2n_cipher_suite s2n_rsa_with_aes_128_cbc_sha256;
extern struct s2n_cipher_suite s2n_rsa_with_aes_256_cbc_sha256;
extern struct s2n_cipher_suite s2n_dhe_rsa_with_aes_128_cbc_sha256;
extern struct s2n_cipher_suite s2n_dhe_rsa_with_aes_256_cbc_sha256;
extern struct s2n_cipher_suite s2n_rsa_with_aes_128_gcm_sha256;
extern struct s2n_cipher_suite s2n_rsa_with_aes_256_gcm_sha384;
extern struct s2n_cipher_suite s2n_dhe_rsa_with_aes_128_gcm_sha256;
extern struct s2n_cipher_suite s2n_dhe_rsa_with_aes_256_gcm_sha384;
extern struct s2n_cipher_suite s2n_ecdhe_rsa_with_3des_ede_cbc_sha;
extern struct s2n_cipher_suite s2n_ecdhe_rsa_with_aes_128_cbc_sha;
extern struct s2n_cipher_suite s2n_ecdhe_rsa_with_aes_256_cbc_sha;
extern struct s2n_cipher_suite s2n_ecdhe_rsa_with_aes_128_cbc_sha256;
extern struct s2n_cipher_suite s2n_ecdhe_rsa_with_aes_256_cbc_sha384;
extern struct s2n_cipher_suite s2n_ecdhe_rsa_with_aes_128_gcm_sha256;
extern struct s2n_cipher_suite s2n_ecdhe_rsa_with_aes_256_gcm_sha384;
extern struct s2n_cipher_suite s2n_ecdhe_rsa_with_chacha20_poly1305_sha256;
extern struct s2n_cipher_suite s2n_dhe_rsa_with_chacha20_poly1305_sha256;

extern int s2n_cipher_suites_init(void);
extern int s2n_cipher_suites_cleanup(void);
extern struct s2n_cipher_suite *s2n_cipher_suite_from_wire(const uint8_t cipher_suite[S2N_TLS_CIPHER_SUITE_LEN]);
extern int s2n_set_cipher_as_client(struct s2n_connection *conn, uint8_t wire[S2N_TLS_CIPHER_SUITE_LEN]);
extern int s2n_set_cipher_as_sslv2_server(struct s2n_connection *conn, uint8_t * wire, uint16_t count);
extern int s2n_set_cipher_as_tls_server(struct s2n_connection *conn, uint8_t * wire, uint16_t count);
