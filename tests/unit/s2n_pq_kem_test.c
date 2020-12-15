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
#include "utils/s2n_safety.h"

struct s2n_kem_test_vector {
    const struct s2n_kem *kem;
    bool (*asm_is_enabled)();
    S2N_RESULT (*enable_asm)();
    S2N_RESULT (*disable_asm)();
};

static const struct s2n_kem_test_vector test_vectors[] = {
        {
                .kem = &s2n_bike1_l1_r1,
                .asm_is_enabled = s2n_pq_no_asm_available,
                .enable_asm = s2n_pq_noop_asm,
                .disable_asm = s2n_pq_noop_asm,
        },
        {
                .kem = &s2n_bike1_l1_r2,
                .asm_is_enabled = s2n_pq_no_asm_available,
                .enable_asm = s2n_pq_noop_asm,
                .disable_asm = s2n_pq_noop_asm,
        },
        {
                .kem = &s2n_sike_p503_r1,
                .asm_is_enabled = s2n_pq_no_asm_available,
                .enable_asm = s2n_pq_noop_asm,
                .disable_asm = s2n_pq_noop_asm,
        },
        {
                .kem = &s2n_sike_p434_r2,
                .asm_is_enabled = s2n_sikep434r2_asm_is_enabled,
                .enable_asm = s2n_try_enable_sikep434r2_asm,
                .disable_asm = s2n_disable_sikep434r2_asm,
        },
        {
                .kem = &s2n_kyber_512_r2,
                .asm_is_enabled = s2n_pq_no_asm_available,
                .enable_asm = s2n_pq_noop_asm,
                .disable_asm = s2n_pq_noop_asm,
        },
        {
                .kem = &s2n_kyber_512_90s_r2,
                .asm_is_enabled = s2n_pq_no_asm_available,
                .enable_asm = s2n_pq_noop_asm,
                .disable_asm = s2n_pq_noop_asm,
        },
};

/* EXPECT_SUCCESS checks explicitly function_call != -1; the PQ KEM functions may return
 * any non-zero int to indicate failure.*/
#define EXPECT_PQ_KEM_SUCCESS( function_call )  EXPECT_EQUAL( (function_call) ,  0 )

int main() {
    BEGIN_TEST();

    for (size_t i = 0; i < s2n_array_len(test_vectors); i++) {
        const struct s2n_kem_test_vector vector = test_vectors[i];
        const struct s2n_kem *kem = vector.kem;

        DEFER_CLEANUP(struct s2n_blob public_key = { 0 }, s2n_free);
        EXPECT_SUCCESS(s2n_alloc(&public_key, kem->public_key_length));

        DEFER_CLEANUP(struct s2n_blob private_key = { 0 }, s2n_free);
        EXPECT_SUCCESS(s2n_alloc(&private_key, kem->private_key_length));

        DEFER_CLEANUP(struct s2n_blob client_shared_secret = { 0 }, s2n_free);
        EXPECT_SUCCESS(s2n_alloc(&client_shared_secret, kem->shared_secret_key_length));

        DEFER_CLEANUP(struct s2n_blob server_shared_secret = { 0 }, s2n_free);
        EXPECT_SUCCESS(s2n_alloc(&server_shared_secret, kem->shared_secret_key_length));

        DEFER_CLEANUP(struct s2n_blob ciphertext = { 0 }, s2n_free);
        EXPECT_SUCCESS(s2n_alloc(&ciphertext, kem->ciphertext_length));

        if (s2n_pq_is_enabled()) {
            /* Test the C code */
            EXPECT_OK(vector.disable_asm());
            EXPECT_PQ_KEM_SUCCESS(kem->generate_keypair(public_key.data, private_key.data));
            EXPECT_PQ_KEM_SUCCESS(kem->encapsulate(ciphertext.data, client_shared_secret.data, public_key.data));
            EXPECT_PQ_KEM_SUCCESS(kem->decapsulate(server_shared_secret.data, ciphertext.data, private_key.data));
            EXPECT_BYTEARRAY_EQUAL(server_shared_secret.data, client_shared_secret.data, kem->shared_secret_key_length);

            /* Test the assembly, if available */
            EXPECT_OK(vector.enable_asm());
            if (vector.asm_is_enabled()) {
                EXPECT_SUCCESS(s2n_blob_zero(&public_key));
                EXPECT_SUCCESS(s2n_blob_zero(&private_key));
                EXPECT_SUCCESS(s2n_blob_zero(&client_shared_secret));
                EXPECT_SUCCESS(s2n_blob_zero(&server_shared_secret));
                EXPECT_SUCCESS(s2n_blob_zero(&ciphertext));

                EXPECT_PQ_KEM_SUCCESS(kem->generate_keypair(public_key.data, private_key.data));
                EXPECT_PQ_KEM_SUCCESS(kem->encapsulate(ciphertext.data, client_shared_secret.data, public_key.data));
                EXPECT_PQ_KEM_SUCCESS(kem->decapsulate(server_shared_secret.data, ciphertext.data, private_key.data));
                EXPECT_BYTEARRAY_EQUAL(server_shared_secret.data, client_shared_secret.data, kem->shared_secret_key_length);
            }
        } else {
#if defined(S2N_NO_PQ)
            EXPECT_FAILURE_WITH_ERRNO(kem->generate_keypair(public_key.data, private_key.data), S2N_ERR_UNIMPLEMENTED);
            EXPECT_FAILURE_WITH_ERRNO(kem->encapsulate(ciphertext.data, client_shared_secret.data, public_key.data), S2N_ERR_UNIMPLEMENTED);
            EXPECT_FAILURE_WITH_ERRNO(kem->decapsulate(server_shared_secret.data, ciphertext.data, private_key.data), S2N_ERR_UNIMPLEMENTED);
#else
            EXPECT_FAILURE_WITH_ERRNO(kem->generate_keypair(public_key.data, private_key.data), S2N_ERR_PQ_DISABLED);
            EXPECT_FAILURE_WITH_ERRNO(kem->encapsulate(ciphertext.data, client_shared_secret.data, public_key.data), S2N_ERR_PQ_DISABLED);
            EXPECT_FAILURE_WITH_ERRNO(kem->decapsulate(server_shared_secret.data, ciphertext.data, private_key.data), S2N_ERR_PQ_DISABLED);
#endif
        }
    }

    END_TEST();
}
