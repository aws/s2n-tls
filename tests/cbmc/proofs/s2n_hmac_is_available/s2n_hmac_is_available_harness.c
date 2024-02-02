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

#include "crypto/s2n_fips.h"
#include "crypto/s2n_hmac.h"
#include "crypto/s2n_openssl.h"

#include <assert.h>

void s2n_hmac_is_available_harness()
{
    /* Non-deterministic inputs. */
    s2n_hmac_algorithm hmac_alg;

    /* Operation under verification. */
    bool is_available = s2n_hmac_is_available(hmac_alg);

    /* Postconditions. */
    switch (hmac_alg) {
        case S2N_HASH_MD5:
        case S2N_HMAC_SSLv3_MD5:
        case S2N_HMAC_SSLv3_SHA1:
            assert(is_available == !s2n_is_in_fips_mode() || s2n_libcrypto_is_awslc()); break;
        case S2N_HASH_NONE:
        case S2N_HASH_SHA1:
        case S2N_HASH_SHA224:
        case S2N_HASH_SHA256:
        case S2N_HASH_SHA384:
        case S2N_HASH_SHA512:
            assert(is_available); break;
        default:
            __CPROVER_assert(!is_available, "Unsupported algorithm.");
    }
}
