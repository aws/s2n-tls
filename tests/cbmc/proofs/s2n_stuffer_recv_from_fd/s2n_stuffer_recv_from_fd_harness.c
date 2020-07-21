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
#include "stuffer/s2n_stuffer.h"
#include "utils/s2n_mem.h"

#include <cbmc_proof/cbmc_utils.h>
#include <cbmc_proof/proof_allocators.h>
#include <cbmc_proof/make_common_datastructures.h>

void s2n_stuffer_recv_from_fd_harness() {
    /* Non-deterministic inputs. */
    struct s2n_stuffer *stuffer = cbmc_allocate_s2n_stuffer();
    __CPROVER_assume(s2n_stuffer_is_valid(stuffer));
    int rfd;
    uint32_t len;
    uint32_t bytes_written;

    /* Non-deterministically set initialized (in s2n_mem) to true. */
    if(nondet_bool()) {
        s2n_mem_init();
    }

    /* Save previous state. */
    struct s2n_stuffer old_stuffer = *stuffer;
    struct store_byte_from_buffer old_byte_from_stuffer;
    save_byte_from_blob(&stuffer->blob, &old_byte_from_stuffer);

    /* Operation under verification. */
    if (s2n_stuffer_recv_from_fd(stuffer, rfd, len, &bytes_written) == S2N_SUCCESS) {
       assert(stuffer->write_cursor == old_stuffer.write_cursor + bytes_written);
       assert(s2n_stuffer_is_valid(stuffer));
   }
   assert(stuffer->read_cursor == old_stuffer.read_cursor);
   assert(stuffer->alloced == old_stuffer.alloced);
   assert(stuffer->growable == old_stuffer.growable);
   assert(stuffer->tainted == old_stuffer.tainted);
}
