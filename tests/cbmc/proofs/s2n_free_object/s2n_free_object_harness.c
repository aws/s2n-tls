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
#include "utils/s2n_blob.h"
#include "error/s2n_errno.h"

#include <assert.h>
#include <cbmc_proof/proof_allocators.h>
#include <cbmc_proof/make_common_datastructures.h>
#include <cbmc_proof/cbmc_utils.h>

int munlock(const void *addr, size_t len)
{
    assert(S2N_MEM_IS_WRITABLE(addr,len));
    return nondet_int();
}

long sysconf(int name) { return nondet_long(); }

int s2n_calculate_stacktrace() { return nondet_int(); }

void s2n_free_object_harness() {
    uint32_t size;
    uint8_t * data = can_fail_malloc( size );
    uint8_t * data_copy = data;

    /* Non-deterministically set initialized (in s2n_mem) to true. */
    if(nondet_bool()) {
        s2n_mem_init();
    }

    if (s2n_free_object(&data, size) == 0) {
        assert(data == NULL);

#pragma CPROVER check push
#pragma CPROVER check disable "pointer"
        /* Verify that the memory was zeroed */
        if (size > 0 && data_copy != NULL) {
            size_t i;
            __CPROVER_assume(i < size);
            assert(data_copy[i] == 0);
        }
#pragma CPROVER check pop

    }
}
