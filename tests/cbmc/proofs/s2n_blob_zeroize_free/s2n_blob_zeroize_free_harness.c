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
#include <cbmc_proof/proof_allocators.h>

#include "api/s2n.h"
#include "error/s2n_errno.h"
#include "utils/s2n_blob.h"

void s2n_blob_zeroize_free_harness()
{
    struct s2n_blob *blob = cbmc_allocate_s2n_blob();
    __CPROVER_assume(s2n_blob_is_valid(blob));

    nondet_s2n_mem_init();

    const struct s2n_blob old_blob = *blob;

    if (s2n_blob_zeroize_free(blob) == S2N_SUCCESS) {
        /* If the call worked, assert all bytes in the blob struct
           are zero */
        assert_all_zeroes(blob->data, old_blob.size);
        if (old_blob.size != 0 && s2n_blob_is_growable(&old_blob)) {
            assert(!S2N_MEM_IS_READABLE(blob->data, old_blob.size));
        }
    }
}
