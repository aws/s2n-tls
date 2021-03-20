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

/*
 * There's unreachable code in the CBMC output because s2n_dup calls
 * s2n_alloc, which itself calls s2n_realloc. Since the to blob must
 * be size 0 with a null data pointer to pass the first checks in s2n_dup,
 * many branches of s2n_realloc cannot be executed. This is intentional behavior.
 */

void s2n_dup_harness()
{
    struct s2n_blob *from = cbmc_allocate_s2n_blob();
    struct s2n_blob *to   = cbmc_allocate_s2n_blob();
    __CPROVER_assume(s2n_result_is_ok(s2n_blob_validate(from)));
    __CPROVER_assume(s2n_result_is_ok(s2n_blob_validate(to)));
    const struct s2n_blob         old_from = *from;
    const struct s2n_blob         old_to   = *to;
    struct store_byte_from_buffer old_byte;
    save_byte_from_blob(from, &old_byte);

    nondet_s2n_mem_init();

    if (s2n_dup(from, to) == S2N_SUCCESS) {
        assert(old_from.size != 0);
        assert(old_from.data != NULL);
        assert(old_to.size == 0);
        assert(old_to.data == NULL);
        assert(to->size == from->size);

        uint32_t idx;
        __CPROVER_assume(idx < from->size);
        assert(from->data[ idx ] == to->data[ idx ]);
    }
    assert(s2n_result_is_ok(s2n_blob_validate(from)));
    assert(s2n_result_is_ok(s2n_blob_validate(to)));
    assert_blob_equivalence(from, &old_from, &old_byte);
}
