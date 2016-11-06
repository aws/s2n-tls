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

struct s2n_cipher_preferences {
    uint8_t count;
    uint8_t *wire_format;
    int minimum_protocol_version;
};

/* Key exchange flags that can be OR'ed */
#define S2N_KEY_EXCHANGE_DH       0x01  /* Diffie–Hellman key exchange, including ephemeral */
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

struct s2n_record_algorithm {
    const struct s2n_cipher *cipher;
    s2n_hmac_algorithm hmac_alg;
};

/* Verbose names to avoid confusion with s2n_cipher. Exposed for unit tests */
extern const struct s2n_record_algorithm s2n_record_alg_null;
extern const struct s2n_record_algorithm s2n_record_alg_rc4_md5;
extern const struct s2n_record_algorithm s2n_record_alg_rc4_sha;
extern const struct s2n_record_algorithm s2n_record_alg_3des_sha;
extern const struct s2n_record_algorithm s2n_record_alg_aes128_sha;
extern const struct s2n_record_algorithm s2n_record_alg_aes128_sha_composite;
extern const struct s2n_record_algorithm s2n_record_alg_aes128_sha256;
extern const struct s2n_record_algorithm s2n_record_alg_aes256_sha;
extern const struct s2n_record_algorithm s2n_record_alg_aes256_sha_composite;
extern const struct s2n_record_algorithm s2n_record_alg_aes256_sha256;
extern const struct s2n_record_algorithm s2n_record_alg_aes256_sha384;
extern const struct s2n_record_algorithm s2n_record_alg_aes128_gcm;
extern const struct s2n_record_algorithm s2n_record_alg_aes256_gcm;

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

extern struct s2n_cipher_suite s2n_null_cipher_suite;
extern struct s2n_cipher_preferences *s2n_cipher_preferences_20140601;
extern struct s2n_cipher_preferences *s2n_cipher_preferences_20150202;
extern struct s2n_cipher_preferences *s2n_cipher_preferences_20150214;
extern struct s2n_cipher_preferences *s2n_cipher_preferences_20150306;
extern struct s2n_cipher_preferences *s2n_cipher_preferences_default;

extern int s2n_cipher_suites_init(void);
extern int s2n_cipher_suites_cleanup(void);
extern int s2n_set_cipher_as_client(struct s2n_connection *conn, uint8_t wire[S2N_TLS_CIPHER_SUITE_LEN]);
extern int s2n_set_cipher_as_sslv2_server(struct s2n_connection *conn, uint8_t * wire, uint16_t count);
extern int s2n_set_cipher_as_tls_server(struct s2n_connection *conn, uint8_t * wire, uint16_t count);
