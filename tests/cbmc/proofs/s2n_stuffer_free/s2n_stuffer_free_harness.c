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
#include "stuffer/s2n_stuffer.h"

void s2n_stuffer_free_harness()
{
    /* Non-deterministic inputs. */
    struct s2n_stuffer *stuffer = cbmc_allocate_s2n_stuffer();

    /* Assumptions. */
    nondet_s2n_mem_init();
    __CPROVER_assume(s2n_result_is_ok(s2n_stuffer_validate(stuffer)));
    const bool old_alloced = stuffer ? stuffer->alloced : false;
    struct s2n_blob old_blob;
    old_blob.data = stuffer ? stuffer->blob.data : NULL;
    old_blob.growable = stuffer ? stuffer->blob.growable : NULL;

    /* Operation under verification. */
    int result = s2n_stuffer_free(stuffer);
    if (result == S2N_SUCCESS && stuffer != NULL) {
        assert_all_zeroes((const uint8_t *)stuffer, sizeof(*stuffer));
    } else if (result == S2N_FAILURE && s2n_errno == S2N_ERR_FREE_STATIC_BLOB) {
        assert(!old_blob.growable);
    }

    /* Cleanup after expected error cases, for memory leak check. */
    if ((result == S2N_FAILURE && s2n_errno == S2N_ERR_NOT_INITIALIZED) || !old_blob.growable || !old_alloced) {
        /**
         * 1. `s2n_free` failed _before_ calling `free`, or
         * 2. `stuffer` had a static blow (i.e. with `blob.growable` was `0`), or
         * 3. `stuffer` did not own its blob (i.e. `alloced` was `0`).
         *    Note that `stuffer` is zero-ed out (without `free`-ing the blob),
         *    so we can't use `stuffer->alloced` and `stuffer->blob.data` here.
         */
        free(old_blob.data);
    }
    /* 3. free our heap-allocated `stuffer` since `s2n_stuffer_free` only `free`s the contents. */
    free(stuffer);
}
