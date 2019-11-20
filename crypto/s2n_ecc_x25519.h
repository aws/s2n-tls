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
#include "tls/s2n_tls_parameters.h"
#include "tls/s2n_kex_data.h"
#include "stuffer/s2n_stuffer.h"
#include "crypto/s2n_hash.h"
#include "crypto/s2n_ecc.h"

#define S2N_ECC_EVP_SUPPORTED_CURVES_COUNT 3

extern const struct s2n_ecc_named_curve s2n_ecc_evp_supported_curves[S2N_ECC_EVP_SUPPORTED_CURVES_COUNT];

struct s2n_ecc_evp_params
{
    const struct s2n_ecc_named_curve *negotiated_curve;
    EVP_PKEY *evp_pkey;
};

int s2n_ecc_evp_generate_ephemeral_key(struct s2n_ecc_evp_params *ecc_evp_params);
int s2n_ecc_evp_compute_shared_secret_as_client(struct s2n_ecc_evp_params *ecc_evp_params, struct s2n_blob *Yc_out, struct s2n_blob *shared_key);
int s2n_ecc_evp_compute_shared_secret_as_server(struct s2n_ecc_evp_params *ecc_evp_params, struct s2n_blob *Yc_in, struct s2n_blob *shared_key);
int s2n_ecc_evp_params_free(struct s2n_ecc_evp_params *ecc_evp_params);

