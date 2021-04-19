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
#include <sys/param.h>
#include "utils/s2n_str.h"
#include "utils/s2n_blob.h"
#include "utils/s2n_mem.h"
#include "utils/s2n_safety.h"

char *s2n_strcpy(char *buf, char *last, const char *str) {

/* CBMC pointer checks need to be disabled to compare buf and last for
 * the case where they are the same. */
#pragma CPROVER check push
#pragma CPROVER check disable "pointer"

    if (buf >= last) {
        return buf;
    }

#pragma CPROVER check pop

    if (NULL == str) {
        *buf = '\0';
        return buf;
    }

    /* Free bytes needs to be one byte smaller than size of a storage, 
     * as strncpy always writes '\0', but doesn't include it in n 
     */
    size_t bytes_to_copy = MIN(last - buf - 1, strlen(str));

    char *p = buf;
    if (bytes_to_copy > 0) {
        p = (char *)memcpy(buf, str, bytes_to_copy) + bytes_to_copy;
    }
    *p = '\0';

    return p;
}

int s2n_str_hex_to_bytes_length(const uint8_t *hex, uint32_t *out_bytes_len)
{
    POSIX_ENSURE_REF(hex);
    POSIX_ENSURE_REF(out_bytes_len);

    DEFER_CLEANUP(struct s2n_blob bytes_blob = { 0 }, s2n_free);
    POSIX_GUARD(s2n_alloc(&bytes_blob, strlen((const char *)hex) / 2));
    POSIX_GUARD(s2n_hex_string_to_bytes(hex, &bytes_blob));
    *out_bytes_len = bytes_blob.size; 

    return S2N_SUCCESS;
}

int s2n_str_hex_to_bytes(const uint8_t *hex, uint8_t *out_bytes, uint32_t *out_bytes_len)
{
    POSIX_ENSURE_REF(hex);
    POSIX_ENSURE_REF(out_bytes);
    POSIX_ENSURE_REF(out_bytes_len);

    DEFER_CLEANUP(struct s2n_blob bytes_blob = { 0 }, s2n_free);
    POSIX_GUARD(s2n_alloc(&bytes_blob, strlen((const char *)hex) / 2));
    POSIX_GUARD(s2n_hex_string_to_bytes(hex, &bytes_blob));
    POSIX_ENSURE(*out_bytes_len >= bytes_blob.size, S2N_ERR_INSUFFICIENT_MEM_SIZE);
    *out_bytes_len = bytes_blob.size; 
    POSIX_CHECKED_MEMCPY(out_bytes, bytes_blob.data, bytes_blob.size);

    return S2N_SUCCESS;
}
