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
#include <cbmc_proof/proof_allocators.h>
#include <sys/param.h>

#include "api/s2n.h"
#include "utils/s2n_safety.h"

void s2n_constant_time_copy_or_dont_harness()
{
    /* Non-deterministic inputs. */
    const uint32_t len;
    const uint32_t destlen;
    const uint32_t srclen;
    const uint8_t  dont;
    __CPROVER_assume(len < MAX_ARR_LEN);
    __CPROVER_assume(destlen >= len);
    __CPROVER_assume(srclen >= len);
    uint8_t *dest = can_fail_malloc(destlen);
    uint8_t *src  = can_fail_malloc(srclen);
    uint8_t  old_src_byte;
    uint8_t  old_dest_byte;
    uint32_t index;

    /* Pre-conditions. */
    if (len != 0) {
        __CPROVER_assume(dest != NULL);
        __CPROVER_assume(src != NULL);
        __CPROVER_assume(index < len);
        old_src_byte  = src[ index ];
        old_dest_byte = dest[ index ];
    }

    s2n_constant_time_copy_or_dont(dest, src, len, dont);

    if (dont == 0) {
        if (src != NULL) {
            if (len != 0) { assert(src[ index ] == old_src_byte); }
            if (dest != NULL) {
                uint32_t rand;
                __CPROVER_assume(rand < len);
                assert(dest[ rand ] == src[ rand ]);
            }
        }
    } else {
        if (src != NULL && len != 0) { assert(src[ index ] == old_src_byte); }
        if (dest != NULL && len != 0) { assert(dest[ index ] == old_dest_byte); }
    }
}
