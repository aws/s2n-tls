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

int s2n_hmac_hash_block_size(s2n_hmac_algorithm, uint16_t *);

void s2n_hmac_hash_block_size_harness()
{
    /* Non-deterministic inputs. */
    s2n_hmac_algorithm hmac_alg;
    uint16_t *         block_size = malloc(sizeof(*block_size));

    /* Operation under verification. */
    if (s2n_hmac_hash_block_size(hmac_alg, block_size) == S2N_SUCCESS) {
        /* Post-conditions. */
        switch(hmac_alg) {
            case S2N_HMAC_NONE:
            case S2N_HMAC_MD5:
            case S2N_HMAC_SHA1:
            case S2N_HMAC_SHA224:
            case S2N_HMAC_SSLv3_MD5:
            case S2N_HMAC_SSLv3_SHA1:
            case S2N_HMAC_SHA256:
                assert(*block_size == 64); break;
            case S2N_HMAC_SHA384:
            case S2N_HMAC_SHA512:
                assert(*block_size == 128); break;
            default:
                __CPROVER_assert(0, "Unsupported algorithm.");
        }
    }
}
