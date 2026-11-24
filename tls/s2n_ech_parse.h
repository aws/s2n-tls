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

#include "error/s2n_errno.h"
#include "stuffer/s2n_stuffer.h"
#include "utils/s2n_blob.h"
#include "utils/s2n_result.h"

/* Reads shared by the ECH parsers. Each fails with `error` when `in` is too
 * short, so that every parser reports malformed input with its own error.
 *
 * Blobs are not copied: they point into the stuffer's data.
 */

S2N_RESULT s2n_ech_read_uint8(struct s2n_stuffer *in, uint8_t *out, s2n_error error);
S2N_RESULT s2n_ech_read_uint16(struct s2n_stuffer *in, uint16_t *out, s2n_error error);
/* Reads `size` bytes as a blob pointing into the stuffer's data */
S2N_RESULT s2n_ech_read_bytes(struct s2n_stuffer *in, uint32_t size, struct s2n_blob *out, s2n_error error);
S2N_RESULT s2n_ech_read_uint8_vector(struct s2n_stuffer *in, struct s2n_blob *out, s2n_error error);
S2N_RESULT s2n_ech_read_uint16_vector(struct s2n_stuffer *in, struct s2n_blob *out, s2n_error error);
/* Reads one TLS-style extension: its type, its body, and, unless `extension`
 * is NULL, a blob over the whole type || length || body */
S2N_RESULT s2n_ech_read_extension(struct s2n_stuffer *in, uint16_t *type, struct s2n_blob *body,
        struct s2n_blob *extension, s2n_error error);
