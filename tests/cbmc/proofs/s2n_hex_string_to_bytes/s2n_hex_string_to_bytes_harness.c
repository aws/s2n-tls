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

#include "api/s2n.h"
#include "error/s2n_errno.h"
#include "utils/s2n_blob.h"

#include <cbmc_proof/cbmc_utils.h>
#include <cbmc_proof/proof_allocators.h>
#include <cbmc_proof/make_common_datastructures.h>
#include <string.h>

void s2n_hex_string_to_bytes_harness()
{
    /* Non-deterministic inputs. */
    struct s2n_blob *blob = cbmc_allocate_s2n_blob();
    __CPROVER_assume(s2n_blob_is_valid(blob));
    char *str = ensure_c_str_is_allocated(MAX_STRING_LEN);

    /* Save previous state. */
    struct s2n_blob old_blob = *blob;
    struct store_byte_from_buffer old_byte_from_blob;
    save_byte_from_blob(blob, &old_byte_from_blob);

    /* Operation under verification. */
    if(s2n_hex_string_to_bytes(str, blob) == S2N_SUCCESS) {
        size_t strLength = strlen(str);
        assert(blob->size >= (strLength / 2));
        assert(strLength % 2 == 0);
    } else {
        assert(blob->allocated == old_blob.allocated);
        assert(blob->growable == old_blob.growable);
        assert(blob->size == old_blob.size);
    }
    assert(s2n_blob_is_valid(blob));
}
