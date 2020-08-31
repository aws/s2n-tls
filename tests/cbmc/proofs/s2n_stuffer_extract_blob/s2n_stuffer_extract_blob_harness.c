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
#include "stuffer/s2n_stuffer.h"
#include "utils/s2n_mem.h"

void s2n_stuffer_extract_blob_harness()
{
    /* Non-deterministic inputs. */
    struct s2n_stuffer *stuffer = cbmc_allocate_s2n_stuffer();
    __CPROVER_assume(s2n_stuffer_is_valid(stuffer));
    struct s2n_blob *blob = cbmc_allocate_s2n_blob();
    __CPROVER_assume(s2n_blob_is_valid(blob));

    nondet_s2n_mem_init();

    /* Save previous state. */
    struct s2n_stuffer            old_stuffer = *stuffer;
    struct store_byte_from_buffer old_byte_from_stuffer;
    save_byte_from_blob(&stuffer->blob, &old_byte_from_stuffer);

    /* Operation under verification. */
    if (s2n_stuffer_extract_blob(stuffer, blob) == S2N_SUCCESS) {
        assert(s2n_blob_is_valid(blob));
        assert(blob->size == s2n_stuffer_data_available(stuffer));
        if (blob->size > 0) {
            uint32_t index;
            __CPROVER_assume(index < blob->size);
            assert(blob->data[ index ] == stuffer->blob.data[ stuffer->read_cursor + index ]);
        }
    }

    /* Post-conditions. */
    assert(s2n_stuffer_is_valid(stuffer));
    assert_stuffer_equivalence(stuffer, &old_stuffer, &old_byte_from_stuffer);
}
