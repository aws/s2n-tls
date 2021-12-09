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

#include <cbmc_proof/cbmc_utils.h>
#include <cbmc_proof/make_common_datastructures.h>

#include <tls/s2n_handshake.h>

void s2n_handshake_write_header_harness()
{
    /* Non-deterministic inputs. */
    struct s2n_stuffer *stuffer = cbmc_allocate_s2n_stuffer();
    uint8_t message_type;

    nondet_s2n_mem_init();

    struct s2n_stuffer old_stuffer = {0};
    if(stuffer) old_stuffer = *stuffer;

    /* Operation under verification. */
    if (s2n_handshake_write_header(stuffer, message_type) == S2N_SUCCESS) {
        /* Post-conditions. */
        assert(stuffer->blob.data[old_stuffer.read_cursor] == message_type);
    }
}
