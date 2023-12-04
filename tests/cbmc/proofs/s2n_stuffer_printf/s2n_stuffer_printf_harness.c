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

#include "api/s2n.h"
#include "stuffer/s2n_stuffer.h"
#include "utils/s2n_mem.h"

void s2n_stuffer_printf_harness()
{
    nondet_s2n_mem_init();

    struct s2n_stuffer *stuffer = cbmc_allocate_s2n_stuffer();
    __CPROVER_assume(s2n_result_is_ok(s2n_stuffer_validate(stuffer)));

    char *format = ensure_c_str_is_allocated(MAX_STRING_LEN);

    /* CBMC defines va_list as void** */
    size_t va_list_len;
    __CPROVER_assume(va_list_len >= 0);
    __CPROVER_assume(va_list_len < MAX_STRING_LEN);
    void** va_list_mem = malloc(sizeof(void*) * va_list_len);

    /* Store the stuffer to compare after the write */
    struct s2n_stuffer            old_stuffer = *stuffer;
    struct store_byte_from_buffer old_byte;
    save_byte_from_array(old_stuffer.blob.data, old_stuffer.write_cursor, &old_byte);

    int test_success = s2n_stuffer_vprintf(stuffer, format, va_list_mem);
    assert(s2n_result_is_ok(s2n_stuffer_validate(stuffer)));

    /* The basic stuffer fields should NOT be updated */
    assert(old_stuffer.growable == stuffer->growable);
    assert(old_stuffer.tainted == stuffer->tainted);
    assert(old_stuffer.alloced == stuffer->alloced);

    /* Any previously written data should NOT be updated */
    if (old_stuffer.write_cursor > 0) {
        assert_byte_from_buffer_matches(stuffer->blob.data, &old_byte);
    }

    /* The read cursor should NOT be updated */
    assert(old_stuffer.read_cursor == stuffer->read_cursor);

    /* The write cursor should only be updated on success */
    if (test_success == S2N_SUCCESS) {
        assert(old_stuffer.write_cursor <= stuffer->write_cursor);
    } else {
        assert(old_stuffer.write_cursor == stuffer->write_cursor);
    }
}
