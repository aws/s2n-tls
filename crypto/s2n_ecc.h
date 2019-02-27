/*
 * Copyright 2015 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

#include <openssl/ec.h>

#include "tls/s2n_kex_data.h"
#include "stuffer/s2n_stuffer.h"
#include "crypto/s2n_hash.h"

struct s2n_ecc_named_curve {
    /* See https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-8 */
    uint16_t iana_id;
    /* See nid_list in openssl/ssl/t1_lib.c */
    int libcrypto_nid;
    const char *name;
};

/* An array of supported curves in order of descending preference */
extern const struct s2n_ecc_named_curve s2n_ecc_supported_curves[2];

struct s2n_ecc_params {
    /* Negotiated named curve from s2n_ecc_supported_curves, or NULL if ECC can't be used */
    const struct s2n_ecc_named_curve *negotiated_curve;
    /* The ephemeral key or NULL if ECC is not used. Stores only the server public key in the client mode. */
    EC_KEY *ec_key;
};

int s2n_ecc_generate_ephemeral_key(struct s2n_ecc_params *server_ecc_params);
int s2n_ecc_write_ecc_params(struct s2n_ecc_params *server_ecc_params, struct s2n_stuffer *out, struct s2n_blob *written);
int s2n_ecc_read_ecc_params(struct s2n_stuffer *in, struct s2n_blob *data_to_verify, struct s2n_ecdhe_raw_server_params *data);
int s2n_ecc_parse_ecc_params(struct s2n_ecc_params *server_ecc_params, struct s2n_ecdhe_raw_server_params *data);
int s2n_ecc_compute_shared_secret_as_server(struct s2n_ecc_params *server_ecc_params, struct s2n_stuffer *Yc_in, struct s2n_blob *shared_key);
int s2n_ecc_compute_shared_secret_as_client(struct s2n_ecc_params *server_ecc_params, struct s2n_stuffer *Yc_out, struct s2n_blob *shared_key);
int s2n_ecc_find_supported_curve(struct s2n_blob *iana_ids, const struct s2n_ecc_named_curve **found);
int s2n_ecc_params_free(struct s2n_ecc_params *server_ecc_params);
