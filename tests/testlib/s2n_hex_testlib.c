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

#include "error/s2n_errno.h"
#include "stuffer/s2n_stuffer.h"
#include "testlib/s2n_testlib.h"
#include "utils/s2n_safety.h"

S2N_RESULT s2n_stuffer_alloc_from_hex(struct s2n_stuffer *bytes_out, const char *hex_cstr)
{
    RESULT_ENSURE_REF(bytes_out);
    RESULT_ENSURE_REF(hex_cstr);

    DEFER_CLEANUP(struct s2n_blob hex = { 0 }, s2n_free);
    /* Copying the hex into heap memory to handle the 'const' isn't exactly efficient,
     * but for a testlib method it is sufficient.
     */
    RESULT_GUARD_POSIX(s2n_alloc(&hex, strlen(hex_cstr)));
    RESULT_CHECKED_MEMCPY(hex.data, hex_cstr, hex.size);

    RESULT_GUARD_POSIX(s2n_stuffer_alloc(bytes_out, strlen(hex_cstr) / 2));
    RESULT_GUARD(s2n_stuffer_read_hex(bytes_out, &hex));
    return S2N_RESULT_OK;
}

S2N_RESULT s2n_blob_alloc_from_hex_with_whitespace(struct s2n_blob *bytes_out, const char *hex_cstr)
{
    RESULT_ENSURE_REF(bytes_out);
    RESULT_ENSURE_REF(hex_cstr);

    DEFER_CLEANUP(struct s2n_stuffer hex_in = { 0 }, s2n_stuffer_free);
    RESULT_GUARD_POSIX(s2n_stuffer_alloc(&hex_in, strlen(hex_cstr)));
    for (size_t i = 0; i < strlen(hex_cstr); i++) {
        if (hex_cstr[i] == ' ') {
            continue;
        }
        RESULT_GUARD_POSIX(s2n_stuffer_write_uint8(&hex_in, hex_cstr[i]));
    }
    uint32_t hex_in_size = s2n_stuffer_data_available(&hex_in);
    hex_in.blob.size = hex_in_size;

    DEFER_CLEANUP(struct s2n_blob bytes_out_mem = { 0 }, s2n_free);
    RESULT_GUARD_POSIX(s2n_alloc(&bytes_out_mem, hex_in_size / 2));

    struct s2n_stuffer bytes_out_stuffer = { 0 };
    RESULT_GUARD_POSIX(s2n_stuffer_init(&bytes_out_stuffer, &bytes_out_mem));
    RESULT_GUARD(s2n_stuffer_read_hex(&bytes_out_stuffer, &hex_in.blob));

    *bytes_out = bytes_out_mem;
    ZERO_TO_DISABLE_DEFER_CLEANUP(bytes_out_mem);
    return S2N_RESULT_OK;
}
