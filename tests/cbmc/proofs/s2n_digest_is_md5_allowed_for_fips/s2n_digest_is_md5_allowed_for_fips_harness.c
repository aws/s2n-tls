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

#include <cbmc_proof/make_common_datastructures.h>

#include "crypto/s2n_fips.h"
#include "crypto/s2n_evp.h"
#include "utils/s2n_result.h"

#include <assert.h>

void s2n_digest_is_md5_allowed_for_fips_harness()
{
    /* Non-deterministic inputs. */
    struct s2n_evp_digest *evp_digest = cbmc_allocate_s2n_evp_digest();
    bool *out = malloc(sizeof(*out));

    /* Operation under verification. */
    if (s2n_result_is_ok(s2n_digest_is_md5_allowed_for_fips(evp_digest, out)) && *out) {
        /* Post-conditions. */
        assert(evp_digest != NULL);
        assert(evp_digest->ctx != NULL);
        assert(s2n_is_in_fips_mode());
        assert((evp_digest->ctx->flags & EVP_MD_CTX_FLAG_NON_FIPS_ALLOW));
    }
}
