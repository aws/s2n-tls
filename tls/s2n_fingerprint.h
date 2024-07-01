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

#include "api/s2n.h"
#include "api/unstable/fingerprint.h"
#include "crypto/s2n_hash.h"
#include "stuffer/s2n_stuffer.h"
#include "tls/s2n_client_hello.h"
#include "utils/s2n_result.h"

struct s2n_fingerprint_hash {
    uint32_t bytes_digested;
    struct s2n_stuffer *buffer;
    struct s2n_hash_state *hash;
};
S2N_RESULT s2n_fingerprint_hash_add_char(struct s2n_fingerprint_hash *hash, char c);
S2N_RESULT s2n_fingerprint_hash_add_str(struct s2n_fingerprint_hash *hash, const char *str, size_t str_size);
S2N_RESULT s2n_fingerprint_hash_digest(struct s2n_fingerprint_hash *hash, uint8_t *out, size_t out_size);
bool s2n_fingerprint_hash_do_digest(struct s2n_fingerprint_hash *hash);

struct s2n_fingerprint_method {
    s2n_hash_algorithm hash;
    S2N_RESULT (*fingerprint)(struct s2n_client_hello *ch,
            struct s2n_fingerprint_hash *hash, struct s2n_stuffer *output);
};
extern struct s2n_fingerprint_method ja3_fingerprint;

bool s2n_is_grease_value(uint16_t val);
