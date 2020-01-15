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

#include "tls/s2n_config.h"
#include "tls/s2n_signature_scheme.h"

#include "crypto/s2n_certificate.h"
#include "crypto/s2n_cipher.h"
#include "crypto/s2n_hmac.h"
#include "crypto/s2n_hash.h"
#include "crypto/s2n_pkey.h"
#include "crypto/s2n_signature.h"
#include "crypto/s2n_dhe.h"
#include "crypto/s2n_ecc_evp.h"

#define S2N_TLS_SECRET_LEN             48
#define S2N_TLS_RANDOM_DATA_LEN        32
#define S2N_TLS_SEQUENCE_NUM_LEN        8
#define S2N_TLS_CIPHER_SUITE_LEN        2
#define S2N_SSLv2_CIPHER_SUITE_LEN      3
#define S2N_TLS_FINISHED_LEN           12
#define S2N_SSL_FINISHED_LEN           36
#define S2N_TLS_MAX_IV_LEN             16

/* From RFC 5246 6.2.3.3 */
#define S2N_TLS12_AAD_LEN              13
#define S2N_TLS_MAX_AAD_LEN            S2N_TLS12_AAD_LEN
#define S2N_TLS_GCM_FIXED_IV_LEN        4
#define S2N_TLS_GCM_EXPLICIT_IV_LEN     8
#define S2N_TLS_GCM_IV_LEN            (S2N_TLS_GCM_FIXED_IV_LEN + S2N_TLS_GCM_EXPLICIT_IV_LEN)
#define S2N_TLS_GCM_TAG_LEN            16

/* TLS 1.3 uses only implicit IVs - RFC 8446 5.3 */
#define S2N_TLS13_AAD_LEN               5
#define S2N_TLS13_RECORD_IV_LEN         0
#define S2N_TLS13_FIXED_IV_LEN         12

/* From RFC 7905 */
#define S2N_TLS_CHACHA20_POLY1305_FIXED_IV_LEN    12
#define S2N_TLS_CHACHA20_POLY1305_EXPLICIT_IV_LEN  0
#define S2N_TLS_CHACHA20_POLY1305_IV_LEN          12
#define S2N_TLS_CHACHA20_POLY1305_KEY_LEN         32
#define S2N_TLS_CHACHA20_POLY1305_TAG_LEN         16

/* RFC 5246 7.4.1.2 */
#define S2N_TLS_SESSION_ID_MAX_LEN     32

struct s2n_kem_keypair {
    const struct s2n_kem *negotiated_kem;
    struct s2n_blob public_key;
    struct s2n_blob private_key;
};

struct s2n_crypto_parameters {
    struct s2n_pkey server_public_key;
    struct s2n_pkey client_public_key;
    struct s2n_dh_params server_dh_params;
    struct s2n_ecc_evp_params server_ecc_evp_params;
    struct s2n_ecc_evp_params client_ecc_evp_params[S2N_ECC_EVP_SUPPORTED_CURVES_COUNT];
    struct s2n_kem_keypair s2n_kem_keys;
    struct s2n_blob client_key_exchange_message;
    struct s2n_blob client_pq_kem_extension;

    struct s2n_signature_scheme conn_sig_scheme;

    struct s2n_blob client_cert_chain;
    s2n_cert_type client_cert_type;

    struct s2n_signature_scheme client_cert_sig_scheme;

    struct s2n_cipher_suite *cipher_suite;
    struct s2n_session_key client_key;
    struct s2n_session_key server_key;

    uint8_t rsa_premaster_secret[S2N_TLS_SECRET_LEN];
    uint8_t master_secret[S2N_TLS_SECRET_LEN];
    uint8_t client_random[S2N_TLS_RANDOM_DATA_LEN];
    uint8_t server_random[S2N_TLS_RANDOM_DATA_LEN];
    uint8_t client_implicit_iv[S2N_TLS_MAX_IV_LEN];
    uint8_t server_implicit_iv[S2N_TLS_MAX_IV_LEN];

    struct s2n_hash_state signature_hash;
    struct s2n_hmac_state client_record_mac;
    struct s2n_hmac_state server_record_mac;
    struct s2n_hmac_state record_mac_copy_workspace;
    uint8_t client_sequence_number[S2N_TLS_SEQUENCE_NUM_LEN];
    uint8_t server_sequence_number[S2N_TLS_SEQUENCE_NUM_LEN];
};
