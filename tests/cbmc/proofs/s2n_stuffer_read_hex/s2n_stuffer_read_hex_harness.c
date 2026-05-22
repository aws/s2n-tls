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

#include "api/s2n.h"
#include "stuffer/s2n_stuffer.h"

void s2n_stuffer_read_hex_harness()
{
    nondet_s2n_mem_init();

    struct s2n_stuffer *input = cbmc_allocate_s2n_stuffer();
    __CPROVER_assume(s2n_result_is_ok(s2n_stuffer_validate(input)));

    struct s2n_blob *output = cbmc_allocate_s2n_blob();
    __CPROVER_assume(s2n_result_is_ok(s2n_blob_validate(output)));
    __CPROVER_assume(s2n_blob_is_bounded(output, MAX_BLOB_SIZE - 1));

    struct s2n_stuffer old_input = *input;
    struct s2n_blob old_output = *output;
    struct store_byte_from_buffer input_saved_byte = { 0 };
    save_byte_from_blob(&input->blob, &input_saved_byte);

    s2n_result result = s2n_stuffer_read_hex(input, output);

    /* On success, enough hex to fill the blob was read from the stuffer */
    struct s2n_stuffer expected_input = old_input;
    if (s2n_result_is_ok(result)) {
        expected_input.read_cursor += old_output.size * 2;
    }
    assert(s2n_result_is_ok(s2n_stuffer_validate(input)));
    assert_stuffer_equivalence(input, &expected_input, &input_saved_byte);

    /* Only the data in the blob changes, so check equivalent without a saved byte */
    assert(s2n_result_is_ok(s2n_blob_validate(output)));
    assert_blob_equivalence(output, &old_output, NULL);
}
