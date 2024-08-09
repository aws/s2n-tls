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

void s2n_stuffer_read_uint16_hex_harness()
{
    nondet_s2n_mem_init();

    struct s2n_stuffer *hex_in = cbmc_allocate_s2n_stuffer();
    __CPROVER_assume(s2n_result_is_ok(s2n_stuffer_validate(hex_in)));

    struct s2n_stuffer old_hex_in = *hex_in;
    struct store_byte_from_buffer old_byte = { 0 };
    save_byte_from_blob(&hex_in->blob, &old_byte);

    uint16_t out;
    s2n_stuffer_read_uint16_hex(hex_in, &out);

    size_t expected_read = 4;
    struct s2n_stuffer expected_hex_in = old_hex_in;
    if (expected_hex_in.write_cursor >= expected_hex_in.read_cursor + expected_read) {
        expected_hex_in.read_cursor += expected_read;
    }
    assert(s2n_result_is_ok(s2n_stuffer_validate(hex_in)));
    assert_stuffer_equivalence(hex_in, &expected_hex_in, &old_byte);
}
