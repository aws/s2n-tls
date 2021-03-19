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

void s2n_stuffer_read_token_harness()
{
    struct s2n_stuffer *stuffer = cbmc_allocate_s2n_stuffer();
    __CPROVER_assume(s2n_result_is_ok(s2n_stuffer_validate(stuffer)));
    __CPROVER_assume(s2n_blob_is_bounded(&stuffer->blob, MAX_BLOB_SIZE));
    struct s2n_stuffer *token = cbmc_allocate_s2n_stuffer();
    __CPROVER_assume(s2n_result_is_ok(s2n_stuffer_validate(token)));
    char delim;

    /* Store previous state from the stuffer. */
    struct s2n_stuffer            old_stuffer = *stuffer;
    struct store_byte_from_buffer old_byte_from_stuffer;
    save_byte_from_blob(&stuffer->blob, &old_byte_from_stuffer);

    /* Store previous state from the token. */
    struct s2n_stuffer            old_token = *token;
    struct store_byte_from_buffer old_byte_from_token;
    save_byte_from_blob(&token->blob, &old_byte_from_token);

    nondet_s2n_mem_init();

    if (s2n_stuffer_read_token(stuffer, token, delim) == S2N_SUCCESS) {
        assert(s2n_result_is_ok(s2n_stuffer_validate(token)));
        uint32_t token_size = token->write_cursor - old_token.write_cursor;
        if (token_size != 0)
            assert_bytes_match(token->blob.data + old_token.write_cursor, stuffer->blob.data + old_stuffer.read_cursor,
                               token_size);
    } else {
        assert_stuffer_equivalence(stuffer, &old_stuffer, &old_byte_from_stuffer);
        /*
         * s2n_realloc could fail, so we can only guarantee equivalence of
         * data pointer, but not the elements in it.
         */
        assert(token->blob.data == old_token.blob.data);
        assert(token->blob.size == old_token.blob.size);
        assert(token->read_cursor == old_token.read_cursor);
        assert(token->write_cursor == old_token.write_cursor);
        assert(token->high_water_mark == old_token.high_water_mark);
        assert(token->alloced == old_token.alloced);
        assert(token->growable == old_token.growable);
        assert(token->tainted == old_token.tainted);
    }

    assert_stuffer_immutable_fields_after_read(stuffer, &old_stuffer, &old_byte_from_stuffer);
    assert(s2n_result_is_ok(s2n_stuffer_validate(stuffer)));
}
