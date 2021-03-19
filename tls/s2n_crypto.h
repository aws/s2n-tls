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

#pragma once

#include "tls/s2n_config.h"
#include "tls/s2n_signature_scheme.h"
#include "tls/s2n_crypto_constants.h"
#include "tls/s2n_kem.h"

#include "crypto/s2n_certificate.h"
#include "crypto/s2n_cipher.h"
#include "crypto/s2n_hmac.h"
#include "crypto/s2n_hash.h"
#include "crypto/s2n_pkey.h"
#include "crypto/s2n_signature.h"
#include "crypto/s2n_tls13_keys.h"
#include "crypto/s2n_dhe.h"
#include "crypto/s2n_ecc_evp.h"

struct s2n_crypto_parameters {
    struct s2n_pkey server_public_key;
    struct s2n_pkey client_public_key;
    struct s2n_dh_params server_dh_params;
    struct s2n_ecc_evp_params server_ecc_evp_params;
    const struct s2n_ecc_named_curve *mutually_supported_curves[S2N_ECC_EVP_SUPPORTED_CURVES_COUNT];
    struct s2n_ecc_evp_params client_ecc_evp_params[S2N_ECC_EVP_SUPPORTED_CURVES_COUNT];
    struct s2n_kem_group_params server_kem_group_params;
    struct s2n_kem_group_params *chosen_client_kem_group_params;
    struct s2n_kem_group_params client_kem_group_params[S2N_SUPPORTED_KEM_GROUPS_COUNT];
    const struct s2n_kem_group *mutually_supported_kem_groups[S2N_SUPPORTED_KEM_GROUPS_COUNT];
    struct s2n_kem_params kem_params;
    struct s2n_blob client_key_exchange_message;
    struct s2n_blob client_pq_kem_extension;

    struct s2n_signature_scheme conn_sig_scheme;

    struct s2n_blob client_cert_chain;
    s2n_pkey_type client_cert_pkey_type;

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
    uint8_t client_app_secret[S2N_TLS13_SECRET_MAX_LEN];
    uint8_t server_app_secret[S2N_TLS13_SECRET_MAX_LEN];
    struct s2n_hash_state signature_hash;
    struct s2n_hmac_state client_record_mac;
    struct s2n_hmac_state server_record_mac;
    struct s2n_hmac_state record_mac_copy_workspace;
    uint8_t client_sequence_number[S2N_TLS_SEQUENCE_NUM_LEN];
    uint8_t server_sequence_number[S2N_TLS_SEQUENCE_NUM_LEN];
};
