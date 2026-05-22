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

#include "crypto/s2n_pq.h"
#include "s2n_testlib.h"
#include "tests/testlib/s2n_nist_kats.h"
#include "tls/s2n_kem.h"
#include "utils/s2n_safety.h"

int s2n_kem_recv_ciphertext_fuzz_test_init(const char *kat_file_path, struct s2n_kem_params *kem_params)
{
    POSIX_ENSURE_REF(kat_file_path);
    POSIX_ENSURE_REF(kem_params);
    POSIX_ENSURE_REF(kem_params->kem);

    POSIX_GUARD(s2n_alloc(&kem_params->private_key, kem_params->kem->private_key_length));
    FILE *kat_file = fopen(kat_file_path, "r");
    POSIX_ENSURE_REF(kat_file);
    POSIX_GUARD(ReadHex(kat_file, kem_params->private_key.data, kem_params->kem->private_key_length, "sk = "));
    fclose(kat_file);

    return S2N_SUCCESS;
}

int s2n_kem_recv_ciphertext_fuzz_test(const uint8_t *buf, size_t len, struct s2n_kem_params *kem_params)
{
    POSIX_ENSURE_REF(buf);
    POSIX_ENSURE_REF(kem_params);
    POSIX_ENSURE_REF(kem_params->kem);

    DEFER_CLEANUP(struct s2n_stuffer ciphertext = { 0 }, s2n_stuffer_free);
    POSIX_GUARD(s2n_stuffer_alloc(&ciphertext, len));
    POSIX_GUARD(s2n_stuffer_write_bytes(&ciphertext, buf, len));

    /* Don't GUARD the call to recv_ciphertext().
     * recv_ciphertext() parses the would-be ciphertext bytes from the
     * handshake, then passes them to the KEM's decaps function.
     * recv_ciphertext() may fail appropriately during parsing if the
     * ciphertext bytes do not correspond to TLS specification (e.g.
     * improperly length-encoded).
     *
     * All but one of the KEM's decaps functions are written in such
     * a way that they should never fail, regardless of the input provided
     * by the fuzzer. If the fuzzer-provided "ciphertext" is not a
     * valid PQ ciphertext (and it probably won't be), the decaps function
     * should still succeed and return 0, but the output plaintext will
     * be garbage. Therefore, if recv_ciphertext() fails for these KEMs,
     * it should not have been due to S2N_ERR_PQ_CRYPTO.
     *
     * If PQ is not enabled, then recv_ciphertext() should always fail. */
    int recv_ciphertext_ret = s2n_kem_recv_ciphertext(&ciphertext, kem_params);

    if (s2n_pq_is_enabled() && recv_ciphertext_ret != S2N_SUCCESS) {
        POSIX_ENSURE_NE(s2n_errno, S2N_ERR_PQ_CRYPTO);
    }

    if (!s2n_pq_is_enabled()) {
        POSIX_ENSURE_NE(recv_ciphertext_ret, S2N_SUCCESS);
    }

    /* Shared secret may have been alloc'ed in recv_ciphertext */
    POSIX_GUARD(s2n_free(&kem_params->shared_secret));

    return S2N_SUCCESS;
}

int s2n_kem_recv_public_key_fuzz_test(const uint8_t *buf, size_t len, struct s2n_kem_params *kem_params)
{
    POSIX_ENSURE_REF(buf);
    POSIX_ENSURE_REF(kem_params);
    POSIX_ENSURE_REF(kem_params->kem);

    DEFER_CLEANUP(struct s2n_stuffer public_key = { 0 }, s2n_stuffer_free);
    POSIX_GUARD(s2n_stuffer_alloc(&public_key, len));
    POSIX_GUARD(s2n_stuffer_write_bytes(&public_key, buf, len));

    /* s2n_kem_recv_public_key performs only very basic checks, like ensuring
     * that the public key size is correct. If the received public key passes,
     * we continue by calling s2n_kem_send_ciphertext to attempt to use the key
     * for encryption. */
    if (s2n_kem_recv_public_key(&public_key, kem_params) == S2N_SUCCESS) {
        DEFER_CLEANUP(struct s2n_stuffer out = { 0 }, s2n_stuffer_free);
        POSIX_GUARD(s2n_stuffer_growable_alloc(&out, 8192));
        int send_ct_ret = s2n_kem_send_ciphertext(&out, kem_params);

        /* The KEM encaps functions are written in such a way that
         * s2n_kem_send_ciphertext() should always succeed as long
         * as PQ is enabled, even if the previously received public
         * key is not valid. If PQ is not enabled, send_ciphertext()
         * should always fail because of a PQ crypto errno. */
        if (s2n_pq_is_enabled()) {
            POSIX_ENSURE_EQ(send_ct_ret, S2N_SUCCESS);
        } else {
            POSIX_ENSURE_NE(send_ct_ret, S2N_SUCCESS);
            POSIX_ENSURE_EQ(s2n_errno, S2N_ERR_PQ_CRYPTO);
        }
    }

    /* Clean up */
    POSIX_GUARD(s2n_kem_free(kem_params));

    return S2N_SUCCESS;
}
