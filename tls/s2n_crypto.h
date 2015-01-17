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

#include "tls/s2n_config.h"

#include "crypto/s2n_cipher.h"
#include "crypto/s2n_hmac.h"
#include "crypto/s2n_hash.h"
#include "crypto/s2n_rsa.h"
#include "crypto/s2n_dhe.h"

#define S2N_TLS_SECRET_LEN             48
#define S2N_TLS_RANDOM_DATA_LEN        32
#define S2N_TLS_SEQUENCE_NUM_LEN        8
#define S2N_TLS_CIPHER_SUITE_LEN        2
#define S2N_SSLv2_CIPHER_SUITE_LEN      3
#define S2N_TLS_FINISHED_LEN           12
#define S2N_SSL_FINISHED_LEN           36
#define S2N_TLS_MAX_IV_LEN             16

struct s2n_crypto_parameters {
    struct s2n_rsa_public_key server_rsa_public_key;
    struct s2n_dh_params server_dh_params;
    struct s2n_cert_chain_and_key *chosen_cert_chain;
    s2n_hash_algorithm signature_digest_alg;

    struct s2n_cipher_suite *cipher_suite;
    struct s2n_session_key client_key;
    struct s2n_session_key server_key;

    uint8_t rsa_premaster_secret[S2N_TLS_SECRET_LEN];
    uint8_t master_secret[S2N_TLS_SECRET_LEN];
    uint8_t client_random[S2N_TLS_RANDOM_DATA_LEN];
    uint8_t server_random[S2N_TLS_RANDOM_DATA_LEN];
    uint8_t client_implicit_iv[S2N_TLS_MAX_IV_LEN];
    uint8_t server_implicit_iv[S2N_TLS_MAX_IV_LEN];

    struct s2n_hmac_state client_record_mac;
    struct s2n_hmac_state server_record_mac;
    uint8_t client_sequence_number[S2N_TLS_SEQUENCE_NUM_LEN];
    uint8_t server_sequence_number[S2N_TLS_SEQUENCE_NUM_LEN];
};

extern void s2n_increment_sequence_number(uint8_t sequence_number[S2N_TLS_SEQUENCE_NUM_LEN]);
extern int s2n_zero_sequence_number(uint8_t sequence_number[S2N_TLS_SEQUENCE_NUM_LEN]);
