/*
 * Copyright 2017 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

#include "crypto/s2n_hash.h"
#include "crypto/s2n_signature.h"

#include "stuffer/s2n_stuffer.h"

struct s2n_connection;

struct s2n_sig_hash_alg_pairs {
    /* A matrix representing signature and hash algorithm pairs mapped by the
     * algorithms' TLS values defined here:
     * https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-16 
     */
    uint8_t matrix[TLS_SIGNATURE_ALGORITHM_COUNT][TLS_HASH_ALGORITHM_COUNT];
};

static const s2n_signature_algorithm s2n_preferred_signature_algorithms[] = {
    S2N_SIGNATURE_RSA,
    S2N_SIGNATURE_ECDSA
};

extern int s2n_set_signature_hash_pair_from_preference_list(struct s2n_connection *conn, struct s2n_sig_hash_alg_pairs *sig_hash_algs, 
                                                            s2n_hash_algorithm *hash, s2n_signature_algorithm *sig);
extern int s2n_get_signature_hash_pair_if_supported(struct s2n_stuffer *in, s2n_hash_algorithm *hash_alg, s2n_signature_algorithm *signature_alg);
extern int s2n_send_supported_signature_algorithms(struct s2n_stuffer *out);
extern int s2n_recv_supported_signature_algorithms(struct s2n_connection *conn, struct s2n_stuffer *in, struct s2n_sig_hash_alg_pairs *sig_hash_algs); 
