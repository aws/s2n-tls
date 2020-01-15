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

#include <stdbool.h>
#include <stdint.h>
#include <stdbool.h>



struct s2n_blob {
    uint8_t *data;
    uint32_t size;
    uint32_t allocated;
    unsigned mlocked :1;
    unsigned growable :1;
};


extern bool s2n_blob_is_growable(const struct s2n_blob* b);
extern bool s2n_blob_is_valid(const struct s2n_blob* b);
extern int s2n_blob_init(struct s2n_blob *b, uint8_t * data, uint32_t size);
extern int s2n_blob_zero(struct s2n_blob *b);
extern int s2n_blob_char_to_lower(struct s2n_blob *b);
extern int s2n_hex_string_to_bytes(const char *str, struct s2n_blob *blob);

#define s2n_stack_blob(name, requested_size, maximum)			\
    size_t name ## _requested_size = (requested_size);			\
    uint8_t name ## _buf[(maximum)] = {0};				\
    lte_check(name ## _requested_size, (maximum));			\
    struct s2n_blob name = {0};						\
    GUARD(s2n_blob_init(&name, name ## _buf, name ## _requested_size))

#define S2N_BLOB_LABEL(name, str) \
    static uint8_t name##_data[] = str;   \
    const struct s2n_blob name = { .data = name##_data, .size = sizeof(name##_data) - 1 };

/* The S2N_BLOB_FROM_HEX macro creates a s2n_blob with the contents of a hex string.
 * It is allocated on a stack so there no need to free after use.
 * hex should be a const char[]. This function checks against using char*,
 * because sizeof needs to refer to the buffer length rather than a pointer size */
#define S2N_BLOB_FROM_HEX( name, hex ) \
    s2n_stack_blob(name, (sizeof(hex) - 1) / 2, (sizeof(hex) - 1) / 2); \
    GUARD(s2n_hex_string_to_bytes(hex, &name));
