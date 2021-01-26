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

#include <s2n.h>

#include "crypto/s2n_hmac.h"
#include "utils/s2n_array.h"
#include "utils/s2n_blob.h"
#include "utils/s2n_result.h"

typedef enum {
    S2N_PSK_TYPE_RESUMPTION,
    S2N_PSK_TYPE_EXTERNAL,
} s2n_psk_type;

typedef enum {
    S2N_PSK_KE_UNKNOWN = 0,
    S2N_PSK_KE,
    S2N_PSK_DHE_KE,
} s2n_psk_key_exchange_mode;

typedef enum {
    S2N_PSK_HMAC_SHA224 = 0,
    S2N_PSK_HMAC_SHA256,
    S2N_PSK_HMAC_SHA384,
} s2n_psk_hmac;

struct s2n_external_psk {
    uint8_t *identity;
    size_t identity_length;
    uint8_t *secret;
    size_t secret_length;
    s2n_psk_hmac hmac;
};

struct s2n_psk {
    s2n_psk_type type;
    struct s2n_blob identity;
    struct s2n_blob secret;
    s2n_hmac_algorithm hmac_alg;
    uint32_t obfuscated_ticket_age;
    struct s2n_blob early_secret;
};

struct s2n_psk_identity {
    uint8_t *data;
    uint16_t length;
};

struct s2n_psk_parameters {
    struct s2n_array psk_list;
    uint16_t binder_list_size;
    uint16_t chosen_psk_wire_index;
    struct s2n_psk *chosen_psk;
    s2n_psk_key_exchange_mode psk_ke_mode;
};

/* This function will be labeled S2N_API and become a publicly visible api once we release the psk API. */
int s2n_connection_set_external_psks(struct s2n_connection *conn, struct s2n_external_psk *psk_vec, size_t psk_vec_length);

int s2n_psk_init(struct s2n_psk *psk, s2n_psk_type type);
int s2n_psk_new_identity(struct s2n_psk *psk, const uint8_t *identity, size_t identity_size);
int s2n_psk_new_secret(struct s2n_psk *psk, const uint8_t *secret, size_t secret_size);
int s2n_psk_free(struct s2n_psk *psk);

S2N_RESULT s2n_psk_parameters_init(struct s2n_psk_parameters *params);
S2N_CLEANUP_RESULT s2n_psk_parameters_wipe(struct s2n_psk_parameters *params);

S2N_RESULT s2n_finish_psk_extension(struct s2n_connection *conn);

int s2n_psk_calculate_binder_hash(struct s2n_connection *conn, s2n_hmac_algorithm hmac_alg,
        const struct s2n_blob *partial_client_hello, struct s2n_blob *output_binder_hash);
int s2n_psk_calculate_binder(struct s2n_psk *psk, const struct s2n_blob *binder_hash,
        struct s2n_blob *output_binder);
int s2n_psk_verify_binder(struct s2n_connection *conn, struct s2n_psk *psk,
        const struct s2n_blob *partial_client_hello, struct s2n_blob *binder_to_verify);

typedef int (*s2n_psk_selection_callback)(struct s2n_connection *conn, 
                                          struct s2n_psk_identity *identities, size_t identities_length,
                                          uint16_t *chosen_wire_index);                     
/* This function will be labeled S2N_API and become a publicly visible api once we release the psk API. */
int s2n_config_set_psk_selection_callback(struct s2n_connection *conn, s2n_psk_selection_callback cb);

