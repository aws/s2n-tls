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
#include <cbmc_proof/proof_allocators.h>

#include "crypto/s2n_hmac.h"

void s2n_hmac_xor_pad_size_harness()
{
    /* Non-deterministic inputs. */
    s2n_hmac_algorithm hmac_alg;
    size_t             size;
    uint16_t *         xor_pad_size = bounded_malloc(size);

    /* Operation under verification. */
    if (s2n_hmac_xor_pad_size(hmac_alg, xor_pad_size) == S2N_SUCCESS) {
        /* Post-conditions. */
        assert(IMPLIES(hmac_alg == S2N_HMAC_NONE, *xor_pad_size == 64));
        assert(IMPLIES(hmac_alg == S2N_HMAC_MD5, *xor_pad_size == 64));
        assert(IMPLIES(hmac_alg == S2N_HMAC_SHA1, *xor_pad_size == 64));
        assert(IMPLIES(hmac_alg == S2N_HMAC_SHA224, *xor_pad_size == 64));
        assert(IMPLIES(hmac_alg == S2N_HMAC_SHA256, *xor_pad_size == 64));
        assert(IMPLIES(hmac_alg == S2N_HMAC_SHA384, *xor_pad_size == 128));
        assert(IMPLIES(hmac_alg == S2N_HMAC_SHA512, *xor_pad_size == 128));
        assert(IMPLIES(hmac_alg == S2N_HMAC_SSLv3_MD5, *xor_pad_size == 48));
        assert(IMPLIES(hmac_alg == S2N_HMAC_SSLv3_SHA1, *xor_pad_size == 40));
    }
}
