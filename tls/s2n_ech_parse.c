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

#include "tls/s2n_ech_parse.h"

#include "utils/s2n_safety.h"

S2N_RESULT s2n_ech_read_uint8(struct s2n_stuffer *in, uint8_t *out, s2n_error error)
{
    if (s2n_stuffer_read_uint8(in, out) != S2N_SUCCESS) {
        RESULT_BAIL(error);
    }
    return S2N_RESULT_OK;
}

S2N_RESULT s2n_ech_read_uint16(struct s2n_stuffer *in, uint16_t *out, s2n_error error)
{
    if (s2n_stuffer_read_uint16(in, out) != S2N_SUCCESS) {
        RESULT_BAIL(error);
    }
    return S2N_RESULT_OK;
}

S2N_RESULT s2n_ech_read_bytes(struct s2n_stuffer *in, uint32_t size, struct s2n_blob *out, s2n_error error)
{
    RESULT_ENSURE_REF(out);
    uint8_t *data = s2n_stuffer_raw_read(in, size);
    if (data == NULL) {
        RESULT_BAIL(error);
    }
    RESULT_GUARD_POSIX(s2n_blob_init(out, data, size));
    return S2N_RESULT_OK;
}

S2N_RESULT s2n_ech_read_uint8_vector(struct s2n_stuffer *in, struct s2n_blob *out, s2n_error error)
{
    uint8_t size = 0;
    RESULT_GUARD(s2n_ech_read_uint8(in, &size, error));
    RESULT_GUARD(s2n_ech_read_bytes(in, size, out, error));
    return S2N_RESULT_OK;
}

S2N_RESULT s2n_ech_read_uint16_vector(struct s2n_stuffer *in, struct s2n_blob *out, s2n_error error)
{
    uint16_t size = 0;
    RESULT_GUARD(s2n_ech_read_uint16(in, &size, error));
    RESULT_GUARD(s2n_ech_read_bytes(in, size, out, error));
    return S2N_RESULT_OK;
}

S2N_RESULT s2n_ech_read_extension(struct s2n_stuffer *in, uint16_t *type, struct s2n_blob *body, /* NOLINT(bugprone-easily-swappable-parameters) */
        struct s2n_blob *extension, s2n_error error)
{
    RESULT_ENSURE_REF(in);
    uint32_t start = in->read_cursor;
    RESULT_GUARD(s2n_ech_read_uint16(in, type, error));
    RESULT_GUARD(s2n_ech_read_uint16_vector(in, body, error));
    if (extension) {
        RESULT_GUARD_POSIX(s2n_blob_slice(&in->blob, extension, start, in->read_cursor - start));
    }
    return S2N_RESULT_OK;
}
