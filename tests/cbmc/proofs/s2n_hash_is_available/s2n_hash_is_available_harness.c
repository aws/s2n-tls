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
 * on an "AS IS" BASIS, WITHblock_size WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

#include <cbmc_proof/cbmc_utils.h>

#include "api/s2n.h"
#include "crypto/s2n_hash.h"

void s2n_hash_is_available_harness()
{
    /* Non-deterministic inputs. */
    s2n_hash_algorithm alg;

    /* Operation under verification. */
    bool is_available = s2n_hash_is_available(alg);
    assert(IMPLIES(alg == S2N_HASH_MD5, is_available == !s2n_is_in_fips_mode()));
    assert(IMPLIES(alg == S2N_HASH_MD5_SHA1, is_available == !s2n_is_in_fips_mode()));
    assert(IMPLIES(alg == S2N_HASH_NONE, is_available));
    assert(IMPLIES(alg == S2N_HASH_SHA1, is_available));
    assert(IMPLIES(alg == S2N_HASH_SHA224, is_available));
    assert(IMPLIES(alg == S2N_HASH_SHA256, is_available));
    assert(IMPLIES(alg == S2N_HASH_SHA384, is_available));
    assert(IMPLIES(alg == S2N_HASH_SHA512, is_available));
    assert(IMPLIES(alg == S2N_HASH_SENTINEL, !is_available));
}
