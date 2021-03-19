/*
 * Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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
#include <string.h>

#include "api/s2n.h"
#include "stuffer/s2n_stuffer.h"
#include "utils/s2n_mem.h"

void s2n_stuffer_alloc_ro_from_string_harness()
{
    /* Non-deterministic inputs. */
    struct s2n_stuffer *stuffer = cbmc_allocate_s2n_stuffer();
    __CPROVER_assume(s2n_result_is_ok(s2n_stuffer_validate(stuffer)));
    char *str = ensure_c_str_is_allocated(MAX_STRING_LEN);

    /* Save previous state from stuffer. */
    struct s2n_stuffer            old_stuffer = *stuffer;
    struct store_byte_from_buffer old_byte_from_stuffer;
    save_byte_from_blob(&stuffer->blob, &old_byte_from_stuffer);

    nondet_s2n_mem_init();

    /* Operation under verification. */
    if (s2n_stuffer_alloc_ro_from_string(stuffer, str) == S2N_SUCCESS) {
        /* Post-conditions. */
        uint32_t length = strlen(str);
        assert_bytes_match(stuffer->blob.data, ( const uint8_t * )str, length);
        assert(stuffer->alloced);
        assert(stuffer->blob.size == length + 1);
        assert(stuffer->write_cursor == length);
        assert(stuffer->high_water_mark == length);
    }
    assert(s2n_result_is_ok(s2n_stuffer_validate(stuffer)));
}
