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

#include <assert.h>
#include <cbmc_proof/cbmc_utils.h>
#include <cbmc_proof/make_common_datastructures.h>

#include "api/s2n.h"
#include "utils/s2n_blob.h"

void s2n_free_harness()
{
    /* Non-deterministic inputs. */
    struct s2n_blob *blob = cbmc_allocate_s2n_blob();

    /* Assumptions. */
    nondet_s2n_mem_init();
    __CPROVER_assume(s2n_result_is_ok(s2n_blob_validate(blob)));
    const struct s2n_blob old_blob = *blob;

    /* Operation under verification. */
    int result = s2n_free(blob);
    if (result == S2N_SUCCESS) {
        /* Postconditions. */
        assert(S2N_IMPLIES(old_blob.allocated, blob->data == NULL));
        assert_all_zeroes((const uint8_t *)blob, sizeof(*blob));
        if (old_blob.size != 0 && s2n_blob_is_growable(&old_blob)) {
            assert(!S2N_MEM_IS_READABLE(blob->data, old_blob.size));
        }
    }

    /* Cleanup after expected error cases, for memory leak check. */
    bool failed_before_free = (s2n_errno == S2N_ERR_NOT_INITIALIZED) || (s2n_errno == S2N_ERR_FREE_STATIC_BLOB);
    if ((result != S2N_SUCCESS && failed_before_free) || !s2n_blob_is_growable(blob)) {
        /* 1. `s2n_free` failed _before_ calling `free`, either because:
              (a) s2n was not initialized, or (b) the blob was a static blob.
           2. `blob` is not growable, then `s2n_free` is not supposed to `free` even if successful.
        */
        free(blob->data);
    }
    /* 3. free our heap-allocated `blob` since `s2n_free` only `free`s the contents. */
    free(blob);
}
