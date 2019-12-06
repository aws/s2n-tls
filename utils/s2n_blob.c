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

#include <string.h>
#include <ctype.h>

#include "error/s2n_errno.h"

#include "utils/s2n_safety.h"
#include "utils/s2n_blob.h"

#include <s2n.h>

bool s2n_blob_is_valid(const struct s2n_blob* b)
{
  bool blob_was_valid = S2N_OBJECT_PTR_IS_READABLE(b) && S2N_MEM_IS_READABLE(b->data,b->size);
  return blob_was_valid;
}

int s2n_blob_init(struct s2n_blob *b, uint8_t * data, uint32_t size)
{
    notnull_check(b);
    *b = (struct s2n_blob) {.data = data, .size = size, .growable = 0, .mlocked = 0};
    return 0;
}

int s2n_blob_zero(struct s2n_blob *b)
{
    memset_check(b->data, 0, b->size);

    return 0;
}

int s2n_blob_char_to_lower(struct s2n_blob *b)
{
    uint8_t *ptr = b->data;
    for (int i = 0; i < b->size; i++ ) {
        *ptr = tolower(*ptr);
        ptr++;
    }

    return 0;
}

/* An inverse map from an ascii value to a hexidecimal nibble value
 * accounts for all possible char values, where 255 is invalid value */
static const uint8_t hex_inverse[256] = {
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
      0,   1,   2,   3,   4,   5,   6,   7,   8,   9, 255, 255, 255, 255, 255, 255,
    255,  10,  11,  12,  13,  14,  15, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255,  10,  11,  12,  13,  14,  15, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255
};

/* takes a hex string and writes values in the s2n_blob
 * string needs to a valid hex and blob needs to be large enough */
int s2n_hex_string_to_bytes(const char *str, struct s2n_blob *blob)
{
    notnull_check(str);
    notnull_check(blob);
    uint32_t len = strlen(str);
    /* protects against overflows */
    gte_check(blob->size, len / 2);
    S2N_ERROR_IF(len % 2 != 0, S2N_ERR_INVALID_HEX);

    for (int i = 0; i < len; i += 2) {
        uint8_t high_nibble = hex_inverse[(uint8_t) str[i]];
        S2N_ERROR_IF(high_nibble == 255, S2N_ERR_INVALID_HEX);

        uint8_t low_nibble = hex_inverse[(uint8_t) str[i + 1]];
        S2N_ERROR_IF(low_nibble == 255, S2N_ERR_INVALID_HEX);

        blob->data[i / 2] = high_nibble << 4 | low_nibble;
    }

    return 0;
}
