/*
 * Copyright 2014 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

#include <stdint.h>

struct s2n_blob {
    uint8_t *data;
    uint32_t size;
    uint32_t allocated;
    uint8_t mlocked;
};

extern int s2n_blob_init(struct s2n_blob *b, uint8_t * data, uint32_t size);
extern int s2n_blob_zero(struct s2n_blob *b);

#define s2n_stack_blob(name, requested_size, maximum)                               \
    size_t name ## _requested_size = (requested_size);                              \
    uint8_t name ## _buf[(maximum)] = {0};                                          \
    lte_check(name ## _requested_size, (maximum));                                  \
    struct s2n_blob name = {.data = name ## _buf, .size = name ## _requested_size}
