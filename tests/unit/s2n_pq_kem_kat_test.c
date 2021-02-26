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
#include "tls/s2n_kem.h"
#include "pq-crypto/s2n_pq.h"
#include "tests/testlib/s2n_testlib.h"

struct s2n_kem_test_vector {
    const struct s2n_kem *kem;
    const char *kat_file;
    bool (*asm_is_enabled)();
    S2N_RESULT (*enable_asm)();
    S2N_RESULT (*disable_asm)();
};

static const struct s2n_kem_test_vector test_vectors[] = {
        {
                .kem = &s2n_bike1_l1_r1,
                .kat_file = "kats/bike_r1.kat",
                .asm_is_enabled = s2n_pq_no_asm_available,
                .enable_asm = s2n_pq_noop_asm,
                .disable_asm = s2n_pq_noop_asm,
        },
        {
                .kem = &s2n_bike1_l1_r2,
                .kat_file = "kats/bike_r2.kat",
                .asm_is_enabled = s2n_pq_no_asm_available,
                .enable_asm = s2n_pq_noop_asm,
                .disable_asm = s2n_pq_noop_asm,
        },
        {
                .kem = &s2n_sike_p503_r1,
                .kat_file = "kats/sike_r1.kat",
                .asm_is_enabled = s2n_pq_no_asm_available,
                .enable_asm = s2n_pq_noop_asm,
                .disable_asm = s2n_pq_noop_asm,
        },
        {
                .kem = &s2n_sike_p434_r2,
                .kat_file = "kats/sike_r2.kat",
                .asm_is_enabled = s2n_sikep434r2_asm_is_enabled,
                .enable_asm = s2n_try_enable_sikep434r2_asm,
                .disable_asm = s2n_disable_sikep434r2_asm,
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

    for (size_t i = 0; i < s2n_array_len(test_vectors); i++) {
        const struct s2n_kem_test_vector vector = test_vectors[i];
        const struct s2n_kem *kem = vector.kem;

        /* Test the C code */
        EXPECT_OK(vector.disable_asm());
        EXPECT_SUCCESS(s2n_test_kem_with_kat(kem, vector.kat_file));

        /* Test the assembly, if available */
        EXPECT_OK(vector.enable_asm());
        if (vector.asm_is_enabled()) {
            EXPECT_SUCCESS(s2n_test_kem_with_kat(kem, vector.kat_file));
        }
    }

    END_TEST();
}
