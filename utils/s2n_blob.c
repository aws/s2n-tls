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

#include <string.h>
#include <ctype.h>
#include <sys/param.h>

#include "error/s2n_errno.h"

#include "utils/s2n_safety.h"
#include "utils/s2n_blob.h"

#include <s2n.h>

bool s2n_blob_is_valid(const struct s2n_blob* b)
{
    return S2N_OBJECT_PTR_IS_READABLE(b) &&
           S2N_IMPLIES(b->data == NULL, b->size == 0) &&
           S2N_IMPLIES(b->data == NULL, b->allocated == 0) &&
           S2N_IMPLIES(b->growable == 0, b->allocated == 0) &&
           S2N_IMPLIES(b->growable != 0, b->size <= b->allocated) &&
           S2N_MEM_IS_READABLE(b->data, b->allocated) &&
           S2N_MEM_IS_READABLE(b->data, b->size);
}

int s2n_blob_init(struct s2n_blob *b, uint8_t * data, uint32_t size)
{
    notnull_check(b);
    PRECONDITION_POSIX(S2N_MEM_IS_READABLE(data,size));
    *b = (struct s2n_blob) {.data = data, .size = size, .allocated = 0, .growable = 0};
    POSTCONDITION_POSIX(s2n_blob_is_valid(b));
    return S2N_SUCCESS;
}

int s2n_blob_zero(struct s2n_blob *b)
{
    PRECONDITION_POSIX(s2n_blob_is_valid(b));
    memset_check(b->data, 0, MAX(b->allocated, b->size));
    POSTCONDITION_POSIX(s2n_blob_is_valid(b));
    return S2N_SUCCESS;
}

int s2n_blob_slice(const struct s2n_blob *b, struct s2n_blob *slice, uint32_t offset, uint32_t size)
{
    PRECONDITION_POSIX(s2n_blob_is_valid(b));
    PRECONDITION_POSIX(s2n_blob_is_valid(slice));

    uint32_t slice_size = 0;
    GUARD(s2n_add_overflow(offset, size, &slice_size));
    ENSURE_POSIX(b->size >= slice_size, S2N_ERR_SIZE_MISMATCH);
    slice->data = b->data + offset;
    slice->size = size;
    slice->growable = 0;
    slice->allocated = 0;

    POSTCONDITION_POSIX(s2n_blob_is_valid(slice));
    return S2N_SUCCESS;
}

int s2n_blob_char_to_lower(struct s2n_blob *b)
{
    PRECONDITION_POSIX(s2n_blob_is_valid(b));
    for (size_t i = 0; i < b->size; i++) {
        b->data[i] = tolower(b->data[i]);
    }
    POSTCONDITION_POSIX(s2n_blob_is_valid(b));
    return S2N_SUCCESS;
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
int s2n_hex_string_to_bytes(const uint8_t *str, struct s2n_blob *blob)
{
    notnull_check(str);
    PRECONDITION_POSIX(s2n_blob_is_valid(blob));
    uint32_t len = strlen((const char*)str);
    /* protects against overflows */
    gte_check(blob->size, len / 2);
    S2N_ERROR_IF(len % 2 != 0, S2N_ERR_INVALID_HEX);

    for (size_t i = 0; i < len; i += 2) {
        uint8_t high_nibble = hex_inverse[str[i]];
        S2N_ERROR_IF(high_nibble == 255, S2N_ERR_INVALID_HEX);

        uint8_t low_nibble = hex_inverse[str[i + 1]];
        S2N_ERROR_IF(low_nibble == 255, S2N_ERR_INVALID_HEX);
        blob->data[i / 2] = high_nibble << 4 | low_nibble;
    }

    POSTCONDITION_POSIX(s2n_blob_is_valid(blob));
    return S2N_SUCCESS;
}
