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

    struct s2n_stuffer *output = cbmc_allocate_s2n_stuffer();
    __CPROVER_assume(s2n_result_is_ok(s2n_stuffer_validate(output)));

    struct s2n_blob *hex_in = cbmc_allocate_s2n_blob();
    __CPROVER_assume(s2n_result_is_ok(s2n_blob_validate(hex_in)));
    __CPROVER_assume(s2n_blob_is_bounded(hex_in, MAX_BLOB_SIZE));

    struct s2n_stuffer old_output = *output;
    struct store_byte_from_buffer output_saved_byte = { 0 };
    save_byte_from_blob(&output->blob, &output_saved_byte);
    __CPROVER_assume(output_saved_byte.idx < output->write_cursor);

    struct s2n_blob old_hex_in = *hex_in;
    struct store_byte_from_buffer old_hex_in_byte = { 0 };
    save_byte_from_blob(hex_in, &old_hex_in_byte);

    s2n_result result = s2n_stuffer_read_hex(output, hex_in);

    struct s2n_stuffer expected_bytes_out = old_output;
    struct s2n_blob expected_hex_in = old_hex_in;

    /* On success, the byte equivalent of the hex was written to the stuffer */
    if (s2n_result_is_ok(result)) {
        expected_bytes_out.write_cursor += old_hex_in.size / 2;
        expected_bytes_out.high_water_mark = MAX(expected_bytes_out.write_cursor,
                old_output.high_water_mark);
    }

    /* Memory may be allocated on either success or failure,
     * because we allocated the memory before we start writing. */
    if (output->blob.size > old_output.blob.size) {
        expected_bytes_out.blob = output->blob;
    }

    assert(s2n_result_is_ok(s2n_stuffer_validate(output)));
    assert_stuffer_equivalence(output, &expected_bytes_out, &output_saved_byte);
    assert(s2n_result_is_ok(s2n_blob_validate(hex_in)));
    assert_blob_equivalence(hex_in, &expected_hex_in, &old_hex_in_byte);
}
