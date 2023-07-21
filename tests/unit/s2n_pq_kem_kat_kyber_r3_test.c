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

#include "pq-crypto/s2n_pq.h"
#include "s2n_test.h"
#include "tests/testlib/s2n_testlib.h"

static const struct s2n_kem_kat_test_vector test_vectors[] = {
    {
            .kem = &s2n_kyber_512_r3,
            .kat_file = "kats/kyber_r3.kat",
            .asm_is_enabled = s2n_pq_no_asm_available,
            .enable_asm = s2n_pq_noop_asm,
            .disable_asm = s2n_pq_noop_asm,
    },
    {
            .kem = &s2n_kyber_512_r3,
            .kat_file = "kats/kyber_r3.kat",
            .asm_is_enabled = s2n_kyber512r3_is_avx2_bmi2_enabled,
            .enable_asm = s2n_try_enable_kyber512r3_opt_avx2_bmi2,
            .disable_asm = s2n_disable_kyber512r3_opt_avx2_bmi2,
    },
};

int main()
{
    BEGIN_TEST();
    if (!s2n_pq_is_enabled() || s2n_libcrypto_supports_kyber()) {
        /* The KAT tests rely on the low-level PQ crypto functions;
         * there is nothing to test if PQ is disabled.
         *
         * In the case where we are using AWS-LC backed PQ, we rely on the
         * KAT tests implemented in the AWS-LC repository. Implementing these
         * tests within S2N is impossible due to the lack of AWS-LC interfaces
         * for initializing the RNG. */
        END_TEST();
    }
    EXPECT_OK(s2n_pq_kem_kat_test(test_vectors, s2n_array_len(test_vectors)));
    END_TEST();
}
