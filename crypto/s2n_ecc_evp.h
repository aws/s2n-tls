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

#include "crypto/s2n_ecc.h"

#include <openssl/evp.h>

#include "crypto/s2n_hash.h"
#include "stuffer/s2n_stuffer.h"
#include "tls/s2n_tls_parameters.h"
#include "utils/s2n_safety.h"

#if S2N_OPENSSL_VERSION_AT_LEAST(1, 1, 0) && !defined(LIBRESSL_VERSION_NUMBER)
#define MODERN_EC_SUPPORTED 1
extern const struct s2n_ecc_named_curve s2n_ecc_curve_x25519;
#endif

extern const struct s2n_ecc_named_curve* const s2n_ecc_evp_supported_curves_list[];
extern const size_t s2n_ecc_evp_supported_curves_list_len;

struct s2n_ecc_evp_params {
    const struct s2n_ecc_named_curve *negotiated_curve;
    EVP_PKEY *evp_pkey;
};

int s2n_ecc_evp_generate_ephemeral_key(struct s2n_ecc_evp_params *ecc_evp_params);
int s2n_ecc_evp_compute_shared_secret_from_params(struct s2n_ecc_evp_params *private_ecc_evp_params,
                                                  struct s2n_ecc_evp_params *public_ecc_evp_params,
                                                  struct s2n_blob *shared_key);
int s2n_ecc_evp_params_free(struct s2n_ecc_evp_params *ecc_evp_params);
