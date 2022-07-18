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

void s2n_hmac_hash_alg_harness()
{
    /* Non-deterministic inputs. */
    s2n_hmac_algorithm hmac_alg;
    s2n_hash_algorithm *out = malloc(sizeof(*out));

    /* Operation under verification. */
    if (s2n_hmac_hash_alg(hmac_alg, out) == S2N_SUCCESS) {
        /* Post-conditions. */
        switch(hmac_alg) {
        case S2N_HMAC_NONE:       assert(*out == S2N_HASH_NONE);   break;
        case S2N_HMAC_MD5:        assert(*out == S2N_HASH_MD5);    break;
        case S2N_HMAC_SHA1:       assert(*out == S2N_HASH_SHA1);   break;
        case S2N_HMAC_SHA224:     assert(*out == S2N_HASH_SHA224); break;
        case S2N_HMAC_SHA256:     assert(*out == S2N_HASH_SHA256); break;
        case S2N_HMAC_SHA384:     assert(*out == S2N_HASH_SHA384); break;
        case S2N_HMAC_SHA512:     assert(*out == S2N_HASH_SHA512); break;
        case S2N_HMAC_SSLv3_MD5:  assert(*out == S2N_HASH_MD5);    break;
        case S2N_HMAC_SSLv3_SHA1: assert(*out == S2N_HASH_SHA1);   break;
        default:
            __CPROVER_assert(0, "Unsupported algorithm.");
        }
    }
}
