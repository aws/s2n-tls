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

const struct s2n_key_exchange_algorithm s2n_rsa = {
    .flags = 0,
};

const struct s2n_key_exchange_algorithm s2n_dhe = {
    .flags = S2N_KEY_EXCHANGE_DH | S2N_KEY_EXCHANGE_EPH,
};

const struct s2n_key_exchange_algorithm s2n_ecdhe = {
    .flags = S2N_KEY_EXCHANGE_DH | S2N_KEY_EXCHANGE_EPH | S2N_KEY_EXCHANGE_ECC,
};

/* All of the cipher suites that s2n negotiates, in order of value */
struct s2n_cipher_suite s2n_all_cipher_suites[] = {
    {"RC4-MD5", {TLS_RSA_WITH_RC4_128_MD5}, &s2n_rsa, &s2n_rc4, S2N_HMAC_MD5, S2N_HMAC_SHA256, S2N_SSLv3},  /* 0x00,0x04 */
    {"RC4-SHA", {TLS_RSA_WITH_RC4_128_SHA}, &s2n_rsa, &s2n_rc4, S2N_HMAC_SHA1, S2N_HMAC_SHA256, S2N_SSLv3}, /* 0x00,0x05 */
    {"DES-CBC3-SHA", {TLS_RSA_WITH_3DES_EDE_CBC_SHA}, &s2n_rsa, &s2n_3des, S2N_HMAC_SHA1, S2N_HMAC_SHA256, S2N_SSLv3},  /* 0x00,0x0A */
    {"EDH-RSA-DES-CBC3-SHA", {TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA}, &s2n_dhe, &s2n_3des, S2N_HMAC_SHA1, S2N_HMAC_SHA256, S2N_SSLv3},  /* 0x00,0x16 */
    {"AES128-SHA", {TLS_RSA_WITH_AES_128_CBC_SHA}, &s2n_rsa, &s2n_aes128, S2N_HMAC_SHA1, S2N_HMAC_SHA256, S2N_TLS10},   /* 0x00,0x2F */
    {"DHE-RSA-AES128-SHA", {TLS_DHE_RSA_WITH_AES_128_CBC_SHA}, &s2n_dhe, &s2n_aes128, S2N_HMAC_SHA1, S2N_HMAC_SHA256, S2N_TLS10},   /* 0x00,0x33 */
    {"AES256-SHA", {TLS_RSA_WITH_AES_256_CBC_SHA}, &s2n_rsa, &s2n_aes256, S2N_HMAC_SHA1, S2N_HMAC_SHA256, S2N_TLS10},   /* 0x00,0x35 */
    {"DHE-RSA-AES256-SHA", {TLS_DHE_RSA_WITH_AES_256_CBC_SHA}, &s2n_dhe, &s2n_aes256, S2N_HMAC_SHA1, S2N_HMAC_SHA256, S2N_TLS10},   /* 0x00,0x39 */
    {"AES128-SHA256", {TLS_RSA_WITH_AES_128_CBC_SHA256}, &s2n_rsa, &s2n_aes128, S2N_HMAC_SHA256, S2N_HMAC_SHA256, S2N_TLS12},   /* 0x00,0x3C */
    {"AES256-SHA256", {TLS_RSA_WITH_AES_256_CBC_SHA256}, &s2n_rsa, &s2n_aes256, S2N_HMAC_SHA256, S2N_HMAC_SHA256, S2N_TLS12},   /* 0x00,0x3D */
    {"DHE-RSA-AES128-SHA256", {TLS_DHE_RSA_WITH_AES_128_CBC_SHA256}, &s2n_dhe, &s2n_aes128, S2N_HMAC_SHA256, S2N_HMAC_SHA256, S2N_TLS12},   /* 0x00,0x67 */
    {"DHE-RSA-AES256-SHA256", {TLS_DHE_RSA_WITH_AES_256_CBC_SHA256}, &s2n_dhe, &s2n_aes256, S2N_HMAC_SHA256, S2N_HMAC_SHA256, S2N_TLS12},   /* 0x00,0x6B */
    {"AES128-GCM-SHA256", {TLS_RSA_WITH_AES_128_GCM_SHA256}, &s2n_rsa, &s2n_aes128_gcm, S2N_HMAC_NONE, S2N_HMAC_SHA256, S2N_TLS12}, /* 0x00,0x9C */
    {"AES256-GCM-SHA384", {TLS_RSA_WITH_AES_256_GCM_SHA384}, &s2n_rsa, &s2n_aes256_gcm, S2N_HMAC_NONE, S2N_HMAC_SHA384, S2N_TLS12}, /* 0x00,0x9D */
    {"DHE-RSA-AES128-GCM-SHA256", {TLS_DHE_RSA_WITH_AES_128_GCM_SHA256}, &s2n_dhe, &s2n_aes128_gcm, S2N_HMAC_NONE, S2N_HMAC_SHA256, S2N_TLS12}, /* 0x00,0x9E */
    {"ECDHE-RSA-DES-CBC3-SHA", {TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA}, &s2n_ecdhe, &s2n_3des, S2N_HMAC_SHA1, S2N_HMAC_SHA256, S2N_TLS10},    /* 0xC0,0x12 */
    {"ECDHE-RSA-AES128-SHA", {TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA}, &s2n_ecdhe, &s2n_aes128, S2N_HMAC_SHA1, S2N_HMAC_SHA256, S2N_TLS10}, /* 0xC0,0x13 */
    {"ECDHE-RSA-AES256-SHA", {TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA}, &s2n_ecdhe, &s2n_aes256, S2N_HMAC_SHA1, S2N_HMAC_SHA256, S2N_TLS10}, /* 0xC0,0x14 */
    {"ECDHE-RSA-AES128-SHA256", {TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256}, &s2n_ecdhe, &s2n_aes128, S2N_HMAC_SHA256, S2N_HMAC_SHA256, S2N_TLS12}, /* 0xC0,0x27 */
    {"ECDHE-RSA-AES256-SHA384", {TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384}, &s2n_ecdhe, &s2n_aes256, S2N_HMAC_SHA384, S2N_HMAC_SHA384, S2N_TLS12}, /* 0xC0,0x28 */
    {"ECDHE-RSA-AES128-GCM-SHA256", {TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256}, &s2n_ecdhe, &s2n_aes128_gcm, S2N_HMAC_NONE, S2N_HMAC_SHA256, S2N_TLS12},   /* 0xC0,0x2F */
    {"ECDHE-RSA-AES256-GCM-SHA384", {TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384}, &s2n_ecdhe, &s2n_aes256_gcm, S2N_HMAC_NONE, S2N_HMAC_SHA384, S2N_TLS12},   /* 0xC0,0x30 */
};

/* This is the initial cipher suite, but is never negotiated */
struct s2n_cipher_suite s2n_null_cipher_suite = { "TLS_NULL_WITH_NULL_NULL", {TLS_NULL_WITH_NULL_NULL}, &s2n_rsa, &s2n_null_cipher, S2N_HMAC_NONE };

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
    /* See if the cipher is one we support */
    conn->secure.cipher_suite = s2n_cipher_suite_match(wire);
    if (conn->secure.cipher_suite == NULL) {
        S2N_ERROR(S2N_ERR_CIPHER_NOT_SUPPORTED);
    }

    return 0;
}

static int s2n_wire_ciphers_contain(uint8_t * match, uint8_t * wire, uint32_t count, uint32_t cipher_suite_len)
{
    for (int i = 0; i < count; i++) {
        uint8_t *theirs = wire + (i * cipher_suite_len) + (cipher_suite_len - S2N_TLS_CIPHER_SUITE_LEN);

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
    if (conn->client_protocol_version < S2N_TLS12) {
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
        uint8_t *ours = conn->config->cipher_preferences->wire_format + (i * S2N_TLS_CIPHER_SUITE_LEN);

        if (s2n_wire_ciphers_contain(ours, wire, count, cipher_suite_len)) {
            /* We have a match */
            struct s2n_cipher_suite *match = s2n_cipher_suite_match(ours);

            /* This should never happen */
            if (match == NULL) {
                S2N_ERROR(S2N_ERR_CIPHER_NOT_SUPPORTED);
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
