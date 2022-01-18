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
#include <sys/param.h>

#include "api/s2n.h"
#include "stuffer/s2n_stuffer.h"
#include "utils/s2n_mem.h"

void s2n_stuffer_writev_bytes_harness()
{
    /* Non-deterministic inputs. */
    struct s2n_stuffer *stuffer = cbmc_allocate_s2n_stuffer();
    __CPROVER_assume(s2n_result_is_ok(s2n_stuffer_validate(stuffer)));

    size_t iov_count;
    __CPROVER_assume(iov_count < MAX_IOVEC_SIZE);
    struct iovec *iov = malloc(iov_count * sizeof(*iov));
    __CPROVER_assume(iov != NULL);
    for (int i = 0; i < iov_count; i++) {
        iov[ i ].iov_base = malloc(iov[ i ].iov_len);
    }

    uint32_t offs;
    uint32_t size;

    nondet_s2n_mem_init();

    /* Save previous state from stuffer. */
    struct s2n_stuffer            old_stuffer = *stuffer;
    struct store_byte_from_buffer old_byte_from_stuffer;
    save_byte_from_blob(&stuffer->blob, &old_byte_from_stuffer);

    /* Operation under verification. */
    if (s2n_stuffer_writev_bytes(stuffer, iov, iov_count, offs, size) == S2N_SUCCESS) {
        /* Post-conditions. */
        assert(s2n_result_is_ok(s2n_stuffer_validate(stuffer)));
    }
}
