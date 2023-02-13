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

typedef enum {
    S2N_FINGERPRINT_JA3,
} s2n_fingerprint_type;

int s2n_client_hello_get_fingerprint_hash(struct s2n_client_hello *ch, s2n_fingerprint_type type, uint32_t max_hash_size,
        uint8_t *hash, uint32_t *hash_size, uint32_t *str_size);
int s2n_client_hello_get_fingerprint_string(struct s2n_client_hello *ch, s2n_fingerprint_type type, uint32_t max_size,
        uint8_t *output, uint32_t *output_size);
