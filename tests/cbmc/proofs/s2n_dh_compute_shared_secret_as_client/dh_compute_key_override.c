/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"). You may not use
 * this file except in compliance with the License. A copy of the License is
 * located at
 *
 *     http://aws.amazon.com/apache2.0/
 *
 * or in the "license" file accompanying this file. This file is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied. See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * Proof-local override for DH_size and DH_compute_key that ensures
 * DH_size returns a consistent value for the same DH object, and
 * DH_compute_key returns a value <= DH_size.
 *
 * The submodule's dh_override.c makes DH_size return a fresh
 * nondeterministic value on each call, which causes CBMC to explore
 * impossible states where the allocation size differs from the
 * expected size passed to s2n_dh_pad_shared_secret.
 */

#include <openssl/dh.h>
#include <assert.h>
#include <cbmc_proof/nondet.h>

/* Use a global to ensure DH_size returns the same value across calls
 * for the same proof run. This is sound because in reality DH_size
 * is deterministic for a given DH object. */
static int dh_size_value = 0;
static bool dh_size_initialized = false;

int DH_size(const DH *dh)
{
    assert(dh != NULL);
    assert(dh->p != NULL);
    if (!dh_size_initialized) {
        int size;
        __CPROVER_assume(size > 0 && size <= 512);
        dh_size_value = size;
        dh_size_initialized = true;
    }
    return dh_size_value;
}

int DH_compute_key(unsigned char *key, const BIGNUM *pub_key, DH *dh)
{
    assert(pub_key != NULL);
    assert(dh != NULL);
    if (nondet_bool()) {
        /* Success: return a value between 1 and DH_size(dh).
         * In reality DH_compute_key always returns <= DH_size(dh). */
        int result;
        int max_size = DH_size(dh);
        __CPROVER_assume(result > 0 && result <= max_size);
        return result;
    }
    return -1;
}
