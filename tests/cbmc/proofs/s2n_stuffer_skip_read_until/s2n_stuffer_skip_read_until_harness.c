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
#include <string.h>

#include "api/s2n.h"
#include "stuffer/s2n_stuffer.h"

void s2n_stuffer_skip_read_until_harness()
{
    /* Non-deterministic inputs. */
    struct s2n_stuffer *stuffer = cbmc_allocate_s2n_stuffer();
    __CPROVER_assume(s2n_result_is_ok(s2n_stuffer_validate(stuffer)));
    __CPROVER_assume(s2n_blob_is_bounded(&stuffer->blob, MAX_BLOB_SIZE));
    char *target = nondet_bool() ? ensure_c_str_is_allocated(MAX_STRING_LEN) : NULL;

    /* Save previous state from stuffer. */
    struct s2n_stuffer            old_stuffer = *stuffer;
    struct store_byte_from_buffer old_byte_from_stuffer;
    save_byte_from_blob(&stuffer->blob, &old_byte_from_stuffer);

    /* Operation under verification. */
    size_t len = (target != NULL) ? strlen(target) : 0;
    if (len > 0 && s2n_stuffer_skip_read_until(stuffer, target) == S2N_SUCCESS) {
        if (s2n_stuffer_data_available(stuffer) >= len) {
            uint8_t *actual = stuffer->blob.data + stuffer->read_cursor - len;
            assert((strncmp(( char * )actual, target, len) == 0) || (s2n_stuffer_data_available(stuffer) < len));
        }
    }

    /* Post-conditions. */
    assert_stuffer_immutable_fields_after_read(stuffer, &old_stuffer, &old_byte_from_stuffer);
    assert(s2n_result_is_ok(s2n_stuffer_validate(stuffer)));
}
