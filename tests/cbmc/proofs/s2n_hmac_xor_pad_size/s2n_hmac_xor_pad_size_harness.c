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

#include <cbmc_proof/cbmc_utils.h>

#include "crypto/s2n_hmac.h"

#include <assert.h>

int s2n_hmac_xor_pad_size(s2n_hmac_algorithm, uint16_t *);

void s2n_hmac_xor_pad_size_harness()
{
    /* Non-deterministic inputs. */
    s2n_hmac_algorithm hmac_alg;
    uint16_t *         xor_pad_size = malloc(sizeof(*xor_pad_size));

    /* Operation under verification. */
    if (s2n_hmac_xor_pad_size(hmac_alg, xor_pad_size) == S2N_SUCCESS) {
        /* Postconditions. */
        switch (hmac_alg) {
            case S2N_HASH_NONE:       assert(*xor_pad_size == 64);  break;
            case S2N_HASH_MD5:        assert(*xor_pad_size == 64);  break;
            case S2N_HASH_SHA1:       assert(*xor_pad_size == 64);  break;
            case S2N_HASH_SHA224:     assert(*xor_pad_size == 64);  break;
            case S2N_HASH_SHA256:     assert(*xor_pad_size == 64);  break;
            case S2N_HASH_SHA384:     assert(*xor_pad_size == 128); break;
            case S2N_HASH_SHA512:     assert(*xor_pad_size == 128); break;
            case S2N_HMAC_SSLv3_MD5:  assert(*xor_pad_size == 48);  break;
            case S2N_HMAC_SSLv3_SHA1: assert(*xor_pad_size == 40);  break;
            default:
                __CPROVER_assert(0, "Unsupported algorithm.");
        }
    }
}
