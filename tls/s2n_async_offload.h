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

#include "api/unstable/async_offload.h"
#include "crypto/s2n_signature.h"
#include "tls/s2n_handshake.h"
#include "utils/s2n_blob.h"
#include "utils/s2n_result.h"

typedef S2N_RESULT (*s2n_async_perform_fn)(struct s2n_async_op *op);

struct s2n_async_pkey_verify_data {
    struct s2n_hash_state digest;
    s2n_signature_algorithm sig_alg;
    struct s2n_blob signature;
};

struct s2n_async_op {
    s2n_async_op_type type;
    s2n_async_state async_state;
    unsigned perform_invoked : 1;
    struct s2n_connection *conn;
    s2n_async_perform_fn perform;
    /* Collect arguments required by each operation */
    union {
        struct s2n_async_pkey_verify_data async_pkey_verify;
        /* Add a new struct for each supported op type */
    } op_data;
};

S2N_RESULT s2n_async_offload_cb_invoke(struct s2n_connection *conn, struct s2n_async_op *op);
int s2n_async_op_perform(struct s2n_async_op *op);
S2N_RESULT s2n_async_op_reset(struct s2n_async_op *op, s2n_async_op_type expected_type);
bool s2n_async_is_op_in_allow_list(struct s2n_config *config, s2n_async_op_type op_type);
