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

void s2n_stuffer_write_uint8_hex_harness()
{
    nondet_s2n_mem_init();

    struct s2n_stuffer *hex_out = cbmc_allocate_s2n_stuffer();
    __CPROVER_assume(s2n_result_is_ok(s2n_stuffer_validate(hex_out)));

    struct s2n_stuffer old_hex_out = *hex_out;
    struct store_byte_from_buffer old_hex_out_byte = { 0 };
    save_byte_from_blob(&hex_out->blob, &old_hex_out_byte);
    __CPROVER_assume(old_hex_out_byte.idx < hex_out->write_cursor);

    uint8_t byte_in = nondet_uint8_t();
    s2n_result result = s2n_stuffer_write_uint8_hex(hex_out, byte_in);

    struct s2n_stuffer expected_hex_out = old_hex_out;
    size_t expected_written = 2;
    size_t test_offset = nondet_size_t();
    __CPROVER_assume(0 <= test_offset);
    __CPROVER_assume(test_offset < expected_written);

    if (s2n_result_is_ok(result)) {
        /* On success, the hex equivalent of the bytes is written to the stuffer */
        expected_hex_out.write_cursor += expected_written;
        expected_hex_out.high_water_mark = MAX(expected_hex_out.write_cursor,
                old_hex_out.high_water_mark);

        /* New bytes written should match the expected hex pattern */
        uint8_t c = hex_out->blob.data[old_hex_out.write_cursor + test_offset];
        assert(('0' <= c && c <= '9') || ('a' <= c && c <= 'f'));
    }

    /* Memory may be allocated on either success or failure,
     * because we allocated the memory before we start writing. */
    if (hex_out->blob.size > old_hex_out.blob.size) {
        expected_hex_out.blob = hex_out->blob;
    }

    assert(s2n_result_is_ok(s2n_stuffer_validate(hex_out)));
    assert_stuffer_equivalence(hex_out, &expected_hex_out, &old_hex_out_byte);
}
