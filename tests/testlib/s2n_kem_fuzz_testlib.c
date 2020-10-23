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

#include "s2n_testlib.h"
#include "utils/s2n_safety.h"
#include "tls/s2n_kem.h"
#include "tests/testlib/s2n_nist_kats.h"
#include "pq-crypto/s2n_pq.h"

/* PQ fuzz tests can (and should) run even when PQ is disabled. If PQ is disabled,
 * the wrapper functions defined in s2n_kem.c should gracefully handle error cases
 * without crashing, segfaulting, etc. */

int s2n_kem_recv_ciphertext_fuzz_test_init(const char *kat_file_path, struct s2n_kem_params *kem_params) {
    notnull_check(kat_file_path);
    notnull_check(kem_params);
    notnull_check(kem_params->kem);

    GUARD(s2n_alloc(&kem_params->private_key, kem_params->kem->private_key_length));

    FILE *kat_file = fopen(kat_file_path, "r");
    notnull_check(kat_file);
    GUARD(ReadHex(kat_file, kem_params->private_key.data, kem_params->kem->private_key_length, "sk = "));
    fclose(kat_file);

    return S2N_SUCCESS;
}

int s2n_kem_recv_ciphertext_fuzz_test(const uint8_t *buf, size_t len, struct s2n_kem_params *kem_params) {
    notnull_check(buf);
    notnull_check(kem_params);
    notnull_check(kem_params->kem);

    struct s2n_stuffer ciphertext = { 0 };
    GUARD(s2n_stuffer_growable_alloc(&ciphertext, 8192));
    GUARD(s2n_stuffer_write_bytes(&ciphertext, buf, len));

    /* Don't GUARD here; this will probably fail. */
    s2n_kem_recv_ciphertext(&ciphertext, kem_params);
    if (kem_params->shared_secret.allocated == 0) {
        /* If s2n_kem_recv_ciphertext failed, this probably did not get allocated. */
        GUARD(s2n_alloc(&kem_params->shared_secret, kem_params->kem->shared_secret_key_length));
    }

    s2n_result decaps_result = kem_params->kem->decapsulate(kem_params->shared_secret.data, ciphertext.blob.data,
            kem_params->private_key.data);

    if (s2n_pq_is_enabled()) {
        /* (With one exception) If PQ is enabled, calling kem->decapsulate should never fail, even if
         * the ciphertext is nonsense. The exception is s2n_bike1_l1_r1, which may or may not fail
         * depending on the particular nonsense of the ciphertext. */
        if (kem_params->kem != &s2n_bike1_l1_r1) {
            ENSURE_POSIX(s2n_result_is_ok(decaps_result), S2N_ERR_SAFETY);
        }
    } else {
        /* Calling decapsulate when PQ is disabled should always result in an error */
        ENSURE_POSIX(s2n_result_is_error(decaps_result), S2N_ERR_SAFETY);
    }

    /* Clean up */
    GUARD(s2n_stuffer_free(&ciphertext));
    GUARD(s2n_free(&kem_params->shared_secret));

    return S2N_SUCCESS;
}

int s2n_kem_recv_public_key_fuzz_test(const uint8_t *buf, size_t len, struct s2n_kem_params *kem_params) {
    notnull_check(buf);
    notnull_check(kem_params);
    notnull_check(kem_params->kem);

    struct s2n_stuffer public_key = { 0 };
    GUARD(s2n_stuffer_growable_alloc(&public_key, 8192));
    GUARD(s2n_stuffer_write_bytes(&public_key, buf, len));

    /* s2n_kem_recv_public_key performs only very basic checks, like ensuring
     * that the public key size is correct. If the received public key passes,
     * we continue by calling s2n_kem_send_ciphertext to attempt to use the key
     * for encryption. */
    if (s2n_kem_recv_public_key(&public_key, kem_params) == S2N_SUCCESS) {
        struct s2n_stuffer out = {0};
        GUARD(s2n_stuffer_growable_alloc(&out, 8192));

        /* The PQ KEM functions are written in such a way that s2n_kem_send_ciphertext()
         * should always succeed, even if the public key is not valid, as long as PQ is
         * enabled. If PQ is disabled, s2n_kem_send_ciphertext() should always fail. */
        int send_ciphertext_result = s2n_kem_send_ciphertext(&out, kem_params);

        if (s2n_pq_is_enabled()) {
            ENSURE_POSIX(send_ciphertext_result == S2N_SUCCESS, S2N_ERR_SAFETY);
        } else {
            ENSURE_POSIX(send_ciphertext_result != S2N_SUCCESS, S2N_ERR_SAFETY);
        }

        GUARD(s2n_stuffer_free(&out));
    }

    /* Clean up */
    GUARD(s2n_stuffer_free(&public_key));
    GUARD(s2n_kem_free(kem_params));

    return S2N_SUCCESS;
}
