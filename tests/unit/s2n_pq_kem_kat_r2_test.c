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

#include "s2n_test.h"
#include "pq-crypto/s2n_pq.h"
#include "tests/testlib/s2n_testlib.h"

static const struct s2n_kem_kat_test_vector test_vectors[] = {
        {
                .kem = &s2n_bike1_l1_r2,
                .kat_file = "kats/bike_r2.kat",
                .asm_is_enabled = s2n_pq_no_asm_available,
                .enable_asm = s2n_pq_noop_asm,
                .disable_asm = s2n_pq_noop_asm,
        },
        {
                .kem = &s2n_kyber_512_r2,
                .kat_file = "kats/kyber_r2.kat",
                .asm_is_enabled = s2n_pq_no_asm_available,
                .enable_asm = s2n_pq_noop_asm,
                .disable_asm = s2n_pq_noop_asm,
        },
        {
                .kem = &s2n_kyber_512_90s_r2,
                .kat_file = "kats/kyber_90s_r2.kat",
                .asm_is_enabled = s2n_pq_no_asm_available,
                .enable_asm = s2n_pq_noop_asm,
                .disable_asm = s2n_pq_noop_asm,
        },
};

int main() {
    BEGIN_TEST();
    if (!s2n_pq_is_enabled()) {
        /* The KAT tests rely on the low-level PQ crypto functions;
         * there is nothing to test if PQ is disabled. */
        END_TEST();
    }
    EXPECT_OK(s2n_pq_kem_kat_test(test_vectors, s2n_array_len(test_vectors)));
    END_TEST();
}
