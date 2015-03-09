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

#include "tls/s2n_cipher_suites.h"
#include "tls/s2n_connection.h"
#include "utils/s2n_safety.h"

/* All of the cipher suites that s2n negotiates, in order of value */
struct s2n_cipher_suite s2n_all_cipher_suites[] = {
    {"TLS_RSA_WITH_RC4_128_MD5", {TLS_RSA_WITH_RC4_128_MD5}, S2N_RSA, &s2n_rc4, S2N_HMAC_MD5, S2N_SSLv3},   /* 0x00,0x04 */
    {"TLS_RSA_WITH_RC4_128_SHA", {TLS_RSA_WITH_RC4_128_SHA}, S2N_RSA, &s2n_rc4, S2N_HMAC_SHA1, S2N_SSLv3},  /* 0x00,0x05 */
    {"TLS_RSA_WITH_3DES_EDE_CBC_SHA", {TLS_RSA_WITH_3DES_EDE_CBC_SHA}, S2N_RSA, &s2n_3des, S2N_HMAC_SHA1, S2N_TLS10},   /* 0x00,0x0A */
    {"TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA", {TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA}, S2N_DHE, &s2n_3des, S2N_HMAC_SHA1, S2N_TLS10},   /* 0x00,0x16 */
    {"TLS_RSA_WITH_AES_128_CBC_SHA", {TLS_RSA_WITH_AES_128_CBC_SHA}, S2N_RSA, &s2n_aes128, S2N_HMAC_SHA1, S2N_TLS10},   /* 0x00,0x2F */
    {"TLS_DHE_RSA_WITH_AES_128_CBC_SHA", {TLS_DHE_RSA_WITH_AES_128_CBC_SHA}, S2N_DHE, &s2n_aes128, S2N_HMAC_SHA1, S2N_TLS10},   /* 0x00,0x33 */
    {"TLS_RSA_WITH_AES_256_CBC_SHA", {TLS_RSA_WITH_AES_256_CBC_SHA}, S2N_RSA, &s2n_aes256, S2N_HMAC_SHA1, S2N_TLS10},   /* 0x00,0x35 */
    {"TLS_DHE_RSA_WITH_AES_256_CBC_SHA", {TLS_DHE_RSA_WITH_AES_256_CBC_SHA}, S2N_DHE, &s2n_aes256, S2N_HMAC_SHA1, S2N_TLS10},   /* 0x00,0x39 */
    {"TLS_RSA_WITH_AES_128_CBC_SHA256", {TLS_RSA_WITH_AES_128_CBC_SHA256}, S2N_RSA, &s2n_aes128, S2N_HMAC_SHA256, S2N_TLS12},   /* 0x00,0x3C */
    {"TLS_RSA_WITH_AES_256_CBC_SHA256", {TLS_RSA_WITH_AES_256_CBC_SHA256}, S2N_RSA, &s2n_aes256, S2N_HMAC_SHA256, S2N_TLS12},   /* 0x00,0x3D */
    {"TLS_DHE_RSA_WITH_AES_128_CBC_SHA256", {TLS_DHE_RSA_WITH_AES_128_CBC_SHA256}, S2N_DHE, &s2n_aes128, S2N_HMAC_SHA256, S2N_TLS12},   /* 0x00,0x67 */
    {"TLS_DHE_RSA_WITH_AES_256_CBC_SHA256", {TLS_DHE_RSA_WITH_AES_256_CBC_SHA256}, S2N_DHE, &s2n_aes256, S2N_HMAC_SHA256, S2N_TLS12},   /* 0x00,0x6B */
    {"TLS_RSA_WITH_AES_128_GCM_SHA256", {TLS_RSA_WITH_AES_128_GCM_SHA256}, S2N_RSA, &s2n_aes128_gcm, S2N_HMAC_NONE, S2N_TLS12},   /* 0x00,0x9C */
    {"TLS_DHE_RSA_WITH_AES_128_GCM_SHA256", {TLS_DHE_RSA_WITH_AES_128_GCM_SHA256}, S2N_DHE, &s2n_aes128_gcm, S2N_HMAC_NONE, S2N_TLS12},   /* 0x00,0x9E */
    {"TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA", {TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA}, S2N_ECDHE, &s2n_3des, S2N_HMAC_SHA1, S2N_TLS10},   /* 0xC0,0x12 */
    {"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", {TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA}, S2N_ECDHE, &s2n_aes128, S2N_HMAC_SHA1, S2N_TLS10},   /* 0xC0,0x13 */
    {"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA", {TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA}, S2N_ECDHE, &s2n_aes256, S2N_HMAC_SHA1, S2N_TLS10},   /* 0xC0,0x14 */
    {"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256", {TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256}, S2N_ECDHE, &s2n_aes128, S2N_HMAC_SHA256, S2N_TLS12},   /* 0xC0,0x27 */
    {"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384", {TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384}, S2N_ECDHE, &s2n_aes256, S2N_HMAC_SHA384, S2N_TLS12},   /* 0xC0,0x28 */
    {"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", {TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256}, S2N_ECDHE, &s2n_aes128_gcm, S2N_HMAC_NONE, S2N_TLS12},   /* 0xC0,0x2F */
};

/* This is the initial cipher suite, but is never negotiated */
struct s2n_cipher_suite s2n_null_cipher_suite = { "TLS_NULL_WITH_NULL_NULL", {TLS_NULL_WITH_NULL_NULL}, S2N_RSA, &s2n_null_cipher, S2N_HMAC_NONE };

struct s2n_cipher_suite *s2n_cipher_suite_match(uint8_t cipher_suite[S2N_TLS_CIPHER_SUITE_LEN])
{
    int low = 0;
    int top = (sizeof(s2n_all_cipher_suites) / sizeof(struct s2n_cipher_suite)) - 1;

    /* Perform a textbook binary search */
    while (low <= top) {
        /* Check in the middle */
        int mid = low + ((top - low) / 2);
        int m = memcmp(s2n_all_cipher_suites[mid].value, cipher_suite, 2);

        if (m == 0) {
            return &s2n_all_cipher_suites[mid];
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
    /* See if the pending cipher is one we support */
    conn->pending.cipher_suite = s2n_cipher_suite_match(wire);
    if (conn->pending.cipher_suite == NULL) {
        S2N_ERROR(S2N_ERR_CIPHER_NOT_SUPPORTED);
    }

    return 0;
}

static int s2n_set_cipher_as_server(struct s2n_connection *conn, uint8_t *wire, uint32_t count, uint32_t cipher_suite_len)
{
    uint8_t fallback_scsv[S2N_TLS_CIPHER_SUITE_LEN] = { TLS_FALLBACK_SCSV };


    /* s2n supports only server order */
    for (int i = 0; i < conn->config->cipher_preferences->count; i++) {
        uint8_t *ours = conn->config->cipher_preferences->wire_format + (i * S2N_TLS_CIPHER_SUITE_LEN);
        for (int j = 0; j < count; j++) {
            uint8_t *theirs = wire + (j * cipher_suite_len) + (cipher_suite_len - S2N_TLS_CIPHER_SUITE_LEN);

            if (!memcmp(fallback_scsv, theirs, S2N_TLS_CIPHER_SUITE_LEN)) {
                if (conn->client_protocol_version < S2N_TLS12) {
                    conn->closed = 1;
                    S2N_ERROR(S2N_ERR_FALLBACK_DETECTED);
                }
            }

            if (!memcmp(ours, theirs, S2N_TLS_CIPHER_SUITE_LEN)) {
                /* We have a match */
                struct s2n_cipher_suite *match;
                uint16_t key_exchange_flags;

                match = s2n_cipher_suite_match(ours);
                /* This should never happen */
                if (match == NULL) {
                    S2N_ERROR(S2N_ERR_CIPHER_NOT_SUPPORTED);
                }

                GUARD(s2n_get_key_exchange_flags(match->key_exchange_alg, &key_exchange_flags));

                /* Don't choose DHE key exchange if it's not configured. */
                if (conn->config->dhparams == NULL && match->key_exchange_alg == S2N_DHE) {
                    continue;
                }
                /* Don't choose EC ciphers if the curve was not agreed upon. */
                if (conn->pending.server_ecc_params.negotiated_curve == NULL && (key_exchange_flags & S2N_KEY_EXCHANGE_ECC)) {
                    continue;
                }

                conn->pending.cipher_suite = match;
                return 0;
            }
        }
    }

    S2N_ERROR(S2N_ERR_CIPHER_NOT_SUPPORTED);
}

int s2n_set_cipher_as_sslv2_server(struct s2n_connection *conn, uint8_t *wire, uint16_t count)
{
    return s2n_set_cipher_as_server(conn, wire, count, S2N_SSLv2_CIPHER_SUITE_LEN);
}

int s2n_set_cipher_as_tls_server(struct s2n_connection *conn, uint8_t *wire, uint16_t count)
{
    return s2n_set_cipher_as_server(conn, wire, count, S2N_TLS_CIPHER_SUITE_LEN);
}

int s2n_get_key_exchange_flags(s2n_key_exchange_algorithm alg, uint16_t *flags)
{
    static uint16_t alg_flags[] = {
        [S2N_RSA]           = 0,
        [S2N_DH]            = S2N_KEY_EXCHANGE_DH,
        [S2N_DHE]           = S2N_KEY_EXCHANGE_DH | S2N_KEY_EXCHANGE_EPH,
        [S2N_ECDH]          = S2N_KEY_EXCHANGE_DH | S2N_KEY_EXCHANGE_ECC,
        [S2N_ECDHE]         = S2N_KEY_EXCHANGE_DH | S2N_KEY_EXCHANGE_EPH | S2N_KEY_EXCHANGE_ECC,
        [S2N_ECDHE_ECDSA]   = S2N_KEY_EXCHANGE_DH | S2N_KEY_EXCHANGE_EPH | S2N_KEY_EXCHANGE_ECC,
    };
    *flags = alg_flags[alg];
    return 0;
}

