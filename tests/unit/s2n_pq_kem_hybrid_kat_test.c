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
#include "tls/s2n_cipher_suites.h"
#include "pq-crypto/s2n_pq.h"
#include "tests/testlib/s2n_testlib.h"

struct s2n_kem_hybrid_test_vector {
    const struct s2n_kem *kem;
    struct s2n_cipher_suite *cipher_suite;
    const char *security_policy_name;
    const char *kat_file;
    uint32_t server_key_msg_len;
    uint32_t client_key_msg_len;
    bool (*asm_is_enabled)();
    S2N_RESULT (*enable_asm)();
    S2N_RESULT (*disable_asm)();
};

static const struct s2n_kem_hybrid_test_vector test_vectors[] = {
        {
                .kem = &s2n_bike1_l1_r1,
                .cipher_suite = &s2n_ecdhe_bike_rsa_with_aes_256_gcm_sha384,
                .security_policy_name = "KMS-PQ-TLS-1-0-2019-06",
                .kat_file = "kats/hybrid_ecdhe_bike_r1.kat",
                .server_key_msg_len = 2875,
                .client_key_msg_len = 2610,
                .asm_is_enabled = s2n_pq_no_asm_available,
                .enable_asm = s2n_pq_noop_asm,
                .disable_asm = s2n_pq_noop_asm,
        },
        {
                .kem = &s2n_bike1_l1_r2,
                .cipher_suite = &s2n_ecdhe_bike_rsa_with_aes_256_gcm_sha384,
                .security_policy_name = "KMS-PQ-TLS-1-0-2020-02",
                .kat_file = "kats/hybrid_ecdhe_bike_r2.kat",
                .server_key_msg_len = 3279,
                .client_key_msg_len = 3014,
                .asm_is_enabled = s2n_pq_no_asm_available,
                .enable_asm = s2n_pq_noop_asm,
                .disable_asm = s2n_pq_noop_asm,
        },
        {
                .kem = &s2n_sike_p503_r1,
                .cipher_suite = &s2n_ecdhe_sike_rsa_with_aes_256_gcm_sha384,
                .security_policy_name = "KMS-PQ-TLS-1-0-2019-06",
                .kat_file = "kats/hybrid_ecdhe_sike_r1.kat",
                .server_key_msg_len = 711,
                .client_key_msg_len = 470,
                .asm_is_enabled = s2n_pq_no_asm_available,
                .enable_asm = s2n_pq_noop_asm,
                .disable_asm = s2n_pq_noop_asm,
        },
        {
                .kem = &s2n_sike_p434_r2,
                .cipher_suite = &s2n_ecdhe_sike_rsa_with_aes_256_gcm_sha384,
                .security_policy_name = "KMS-PQ-TLS-1-0-2020-02",
                .kat_file = "kats/hybrid_ecdhe_sike_r2.kat",
                .server_key_msg_len = 663,
                .client_key_msg_len = 414,
                .asm_is_enabled = s2n_sikep434r2_asm_is_enabled,
                .enable_asm = s2n_try_enable_sikep434r2_asm,
                .disable_asm = s2n_disable_sikep434r2_asm,
        },
        {
                .kem = &s2n_kyber_512_r2,
                .cipher_suite = &s2n_ecdhe_kyber_rsa_with_aes_256_gcm_sha384,
                .security_policy_name = "KMS-PQ-TLS-1-0-2020-07",
                .kat_file = "kats/hybrid_ecdhe_kyber_r2.kat",
                .server_key_msg_len = 1133,
                .client_key_msg_len = 804,
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
        const struct s2n_kem_hybrid_test_vector vector = test_vectors[i];
        const struct s2n_kem *kem = vector.kem;
        struct s2n_cipher_suite *cipher_suite = vector.cipher_suite;
        const char *security_policy_name = vector.security_policy_name;
        const char *kat_file = vector.kat_file;
        uint32_t server_key_msg_len = vector.server_key_msg_len;
        uint32_t client_key_msg_len = vector.client_key_msg_len;

        /* Test the C code */
        EXPECT_OK(vector.disable_asm());
        EXPECT_SUCCESS(s2n_test_hybrid_ecdhe_kem_with_kat(kem, cipher_suite, security_policy_name,
                kat_file, server_key_msg_len, client_key_msg_len));

        /* Test the assembly, if available */
        EXPECT_OK(vector.enable_asm());
        if (vector.asm_is_enabled()) {
            EXPECT_SUCCESS(s2n_test_hybrid_ecdhe_kem_with_kat(kem, cipher_suite, security_policy_name,
                    kat_file, server_key_msg_len, client_key_msg_len));
        }
    }

    END_TEST();
}
