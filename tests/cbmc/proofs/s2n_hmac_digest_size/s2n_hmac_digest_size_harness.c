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

void s2n_hmac_digest_size_harness()
{
    /* Non-deterministic inputs. */
    s2n_hmac_algorithm hmac_alg;
    uint8_t *          out = malloc(sizeof(*out));

    /* Operation under verification. */
    if (s2n_hmac_digest_size(hmac_alg, out) == S2N_SUCCESS) {
        /* Post-conditions. */
        switch (hmac_alg) {
        case S2N_HMAC_NONE:       assert(*out == 0);                    break;
        case S2N_HMAC_MD5:        assert(*out == MD5_DIGEST_LENGTH);    break;
        case S2N_HMAC_SHA1:       assert(*out == SHA_DIGEST_LENGTH);    break;
        case S2N_HMAC_SHA224:     assert(*out == SHA224_DIGEST_LENGTH); break;
        case S2N_HMAC_SHA256:     assert(*out == SHA256_DIGEST_LENGTH); break;
        case S2N_HMAC_SHA384:     assert(*out == SHA384_DIGEST_LENGTH); break;
        case S2N_HMAC_SHA512:     assert(*out == SHA512_DIGEST_LENGTH); break;
        case S2N_HMAC_SSLv3_MD5:  assert(*out == MD5_DIGEST_LENGTH);    break;
        case S2N_HMAC_SSLv3_SHA1: assert(*out == SHA_DIGEST_LENGTH);    break;
        default:
            __CPROVER_assert(0, "Unsupported algorithm.");
        }
    }
}
