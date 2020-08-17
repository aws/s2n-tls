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
#include <errno.h>

#include "api/s2n.h"
#include "error/s2n_errno.h"
#include "stuffer/s2n_stuffer.h"

void s2n_stuffer_alloc_ro_from_file_harness()
{
    /* Non-deterministic inputs. */
    struct s2n_stuffer *stuffer = cbmc_allocate_s2n_stuffer();
    char *              file    = nondet_c_str_is_allocated(MAX_STRING_LEN);

    /* Store a byte from the stuffer to compare if the write fails */
    struct s2n_stuffer            old_stuffer;
    struct store_byte_from_buffer old_byte_from_stuffer;
    if (s2n_stuffer_is_valid(stuffer)) {
        old_stuffer = *stuffer;
        save_byte_from_blob(&stuffer->blob, &old_byte_from_stuffer);
    }

    /* Operation under verification. */
    if (s2n_stuffer_alloc_ro_from_file(stuffer, file) == S2N_SUCCESS) {
        assert(s2n_stuffer_is_valid(stuffer));
    } else {
        if (s2n_stuffer_is_valid(stuffer) && errno != EBADF
            && /* The stuffer might not be equivalent if close() fails. */
            errno != EINTR && errno != EIO) {
            assert_stuffer_equivalence(stuffer, &old_stuffer, &old_byte_from_stuffer);
        }
    }
}
