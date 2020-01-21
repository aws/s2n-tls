/*
 * Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

#include <openssl/evp.h>

#include "crypto/s2n_hash.h"
#include "tls/s2n_kex_data.h"
#include "stuffer/s2n_stuffer.h"
#include "tls/s2n_tls_parameters.h"
#include "utils/s2n_safety.h"

struct s2n_ecc_named_curve {
    /* See https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-8 */
    uint16_t iana_id;
    /* See nid_list in openssl/ssl/t1_lib.c */
    int libcrypto_nid;
    const char *name;
    const uint8_t share_size;
};

extern const struct s2n_ecc_named_curve s2n_ecc_curve_secp256r1;
extern const struct s2n_ecc_named_curve s2n_ecc_curve_secp384r1;

#define S2N_ECC_EVP_SUPPORTED_CURVES_COUNT 2
#if S2N_OPENSSL_VERSION_AT_LEAST(1, 1, 0) && !defined(LIBRESSL_VERSION_NUMBER)
#define MODERN_EC_SUPPORTED 1
extern const struct s2n_ecc_named_curve s2n_ecc_curve_x25519;
#else
#define MODERN_EC_SUPPORTED 0
#endif

extern const struct s2n_ecc_named_curve *const s2n_ecc_evp_supported_curves_list[];
extern const size_t s2n_ecc_evp_supported_curves_list_len;

struct s2n_ecc_evp_params {
    const struct s2n_ecc_named_curve *negotiated_curve;
    EVP_PKEY *evp_pkey;
};

int s2n_ecc_evp_generate_ephemeral_key(struct s2n_ecc_evp_params *ecc_evp_params);
int s2n_ecc_evp_compute_shared_secret_from_params(struct s2n_ecc_evp_params *private_ecc_evp_params,
                                                  struct s2n_ecc_evp_params *public_ecc_evp_params,
                                                  struct s2n_blob *shared_key);
int s2n_ecc_evp_write_params_point(struct s2n_ecc_evp_params *ecc_evp_params, struct s2n_stuffer *out);
int s2n_ecc_evp_read_params_point(struct s2n_stuffer *in, int point_size, struct s2n_blob *point_blob);
int s2n_ecc_evp_compute_shared_secret_from_params(struct s2n_ecc_evp_params *private_ecc_evp_params,
                                                  struct s2n_ecc_evp_params *public_ecc_evp_params,
                                                  struct s2n_blob *shared_key);
int s2n_ecc_evp_compute_shared_secret_as_server(struct s2n_ecc_evp_params *server_ecc_evp_params, 
                                            struct s2n_stuffer *Yc_in, struct s2n_blob *shared_key);
int s2n_ecc_evp_compute_shared_secret_as_client(struct s2n_ecc_evp_params *server_ecc_evp_params, 
                                            struct s2n_stuffer *Yc_out, struct s2n_blob *shared_key); 
int s2n_ecc_evp_parse_params_point(struct s2n_blob *point_blob, struct s2n_ecc_evp_params *ecc_evp_params);
int s2n_ecc_evp_write_params(struct s2n_ecc_evp_params *ecc_evp_params, struct s2n_stuffer *out,
                             struct s2n_blob *written);
int s2n_ecc_evp_read_params(struct s2n_stuffer *in, struct s2n_blob *data_to_verify,
                            struct s2n_ecdhe_raw_server_params *raw_server_ecc_params);
int s2n_ecc_evp_parse_params(struct s2n_ecdhe_raw_server_params *raw_server_ecc_params,
                             struct s2n_ecc_evp_params *ecc_evp_params);
int s2n_ecc_evp_find_supported_curve(struct s2n_blob *iana_ids, const struct s2n_ecc_named_curve **found);
int s2n_ecc_evp_params_free(struct s2n_ecc_evp_params *ecc_evp_params);
