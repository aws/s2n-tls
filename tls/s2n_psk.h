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
#include "tls/s2n_kem.h"

#include "crypto/s2n_hash.h"
#include "crypto/s2n_ecc_evp.h"

#define S2N_PSK_VECTOR_MAX_SIZE 7 

struct s2n_psk_identity {
    const char* identity;
    uint32_t obfuscated_ticket_age;
    s2n_hash_algorithm hash_algorithm;
 };

struct s2n_client_psk_config {
    struct s2n_psk_identity psk_vec[S2N_PSK_VECTOR_MAX_SIZE]; 
    uint16_t selected_psk_identity;
    s2n_hash_algorithm selected_hash_algorithm;
    struct s2n_get_psk_callback *cb_func;
    uint64_t psk_vec_len;
 };
