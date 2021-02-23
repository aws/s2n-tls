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
#include <cbmc_proof/proof_allocators.h>
#include <string.h>
#include <sys/param.h>

#include "api/s2n.h"
#include "utils/s2n_str.h"

void s2n_strcpy_harness()
{
    char *         str  = ensure_c_str_is_allocated(MAX_STRING_LEN);
    const uint32_t slen = (str == NULL) ? 0 : strlen(str);
    const uint32_t buflen;
    __CPROVER_assume(buflen < MAX_STRING_LEN);
    char buf[ buflen ];

    /* Last must point to a valid position in buf. */
    const uint32_t last_offset;
    __CPROVER_assume(last_offset < buflen);
    char *                        last = &buf[ last_offset ];
    struct store_byte_from_buffer str_byte;
    save_byte_from_array(str, slen, &str_byte);
    char *result;

    nondet_s2n_mem_init();

    /* Non-deterministically set str to NULL. */
    bool nullstr = nondet_bool();
    result       = s2n_strcpy(buf, last, nullstr ? NULL : str);

    if (buf >= last) {
        assert(result == buf);
    } else if (nullstr) {
        assert(result == buf);
        assert(*buf == '\0');
    } else if (slen > 0) {
        uint32_t rand;
        __CPROVER_assume(rand < MIN(last - buf - 1, slen));
        assert(buf[ rand ] == str[ rand ]);
        assert_byte_from_buffer_matches(str, &str_byte);
        assert(*result == '\0');
    }
}
