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

    DEFER_CLEANUP(struct s2n_stuffer hex = { 0 }, s2n_stuffer_free);
    /* Copying the hex into heap memory to handle the 'const' isn't exactly efficient,
     * but for a testlib method it is sufficient.
     */
    RESULT_GUARD_POSIX(s2n_stuffer_alloc(&hex, strlen(hex_cstr)));
    RESULT_GUARD_POSIX(s2n_stuffer_write_str(&hex, hex_cstr));

    uint32_t bytes_size = strlen(hex_cstr) / 2;
    RESULT_GUARD_POSIX(s2n_stuffer_alloc(bytes_out, bytes_size));
    RESULT_GUARD(s2n_stuffer_read_hex(&hex, &bytes_out->blob));
    RESULT_ENSURE(s2n_stuffer_data_available(&hex) == 0, S2N_ERR_BAD_HEX);
    RESULT_GUARD_POSIX(s2n_stuffer_skip_write(bytes_out, bytes_size));
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

    RESULT_GUARD_POSIX(s2n_alloc(bytes_out, hex_in_size / 2));
    RESULT_GUARD(s2n_stuffer_read_hex(&hex_in, bytes_out));
    RESULT_ENSURE(s2n_stuffer_data_available(&hex_in) == 0, S2N_ERR_BAD_HEX);
    return S2N_RESULT_OK;
}
