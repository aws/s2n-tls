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

#include <sys/param.h>

#include "tls/s2n_kem.h"
#include "tests/testlib/s2n_nist_kats.h"
#include "utils/s2n_mem.h"
#include "utils/s2n_safety.h"
#include "crypto/s2n_fips.h"
#include "pq-crypto/s2n_pq_random.h"

/* We include s2n_drbg.c directly in order to access the static functions in our entropy callbacks. */
#include "crypto/s2n_drbg.c"

#define SEED_LENGTH 48
uint8_t kat_entropy_buff[SEED_LENGTH] = {0};
struct s2n_blob kat_entropy_blob = {.size = SEED_LENGTH, .data = kat_entropy_buff};
struct s2n_drbg drbg_for_pq_kats;

int s2n_pq_kat_rand_init(void) {
    ENSURE_POSIX(s2n_in_unit_test(), S2N_ERR_NOT_IN_UNIT_TEST);
    return S2N_SUCCESS;
}

int s2n_pq_kat_rand_cleanup(void) {
    return S2N_SUCCESS;
}

/* The seed entropy is taken from the NIST KAT file. */
int s2n_pq_kat_seed_entropy(void *ptr, uint32_t size) {
    ENSURE_POSIX(s2n_in_unit_test(), S2N_ERR_NOT_IN_UNIT_TEST);
    notnull_check(ptr);
    eq_check(size, kat_entropy_blob.size);
    memcpy_check(ptr, kat_entropy_buff, size);

    return S2N_SUCCESS;
}

/* Since the NIST KATs were generated without prediction resistance, the
 * mix entropy callback should never be called. */
static int s2n_pq_kat_mix_entropy(void *ptr, uint32_t size) {
    return S2N_FAILURE;
}

/* Adapted from s2n_drbg.c::s2n_drbg_generate(); this allows us to side-step the DRBG
 * prediction resistance that is built in to s2n's DRBG modes. The PQ KATs were generated
 * using AES 256 CTR NO DF NO PR. */
static S2N_RESULT s2n_drbg_generate_for_pq_kat_tests(struct s2n_drbg *drbg, struct s2n_blob *blob) {
    ENSURE(s2n_in_unit_test(), S2N_ERR_NOT_IN_UNIT_TEST);
    ENSURE_REF(drbg);
    ENSURE_REF(drbg->ctx);
    uint8_t zeros_buffer[S2N_DRBG_MAX_SEED_SIZE] = { 0 };
    struct s2n_blob zeros = { .data = zeros_buffer, .size = s2n_drbg_seed_size(drbg) };

    ENSURE(blob->size <= S2N_DRBG_GENERATE_LIMIT, S2N_ERR_DRBG_REQUEST_SIZE);

    /* We do NOT mix in additional entropy */
    GUARD_AS_RESULT(s2n_drbg_bits(drbg, blob));
    GUARD_AS_RESULT(s2n_drbg_update(drbg, &zeros));

    return S2N_RESULT_OK;
}

/* Adapted from s2n_random.c::s2n_get_private_random_data(). */
static S2N_RESULT s2n_get_random_data_for_pq_kat_tests(struct s2n_blob *blob) {
    ENSURE(s2n_in_unit_test(), S2N_ERR_NOT_IN_UNIT_TEST);
    uint32_t offset = 0;
    uint32_t remaining = blob->size;

    while(remaining) {
        struct s2n_blob slice = { 0 };

        GUARD_AS_RESULT(s2n_blob_slice(blob, &slice, offset, MIN(remaining, S2N_DRBG_GENERATE_LIMIT)));;
        GUARD_RESULT(s2n_drbg_generate_for_pq_kat_tests(&drbg_for_pq_kats, &slice));

        remaining -= slice.size;
        offset += slice.size;
    }

    return S2N_RESULT_OK;
}

S2N_RESULT s2n_get_random_bytes_for_pq_kat_tests(uint8_t *buffer, uint32_t num_bytes) {
    ENSURE(s2n_in_unit_test(), S2N_ERR_NOT_IN_UNIT_TEST);
    struct s2n_blob out = { .data = buffer, .size = num_bytes };

    GUARD_RESULT(s2n_get_random_data_for_pq_kat_tests(&out));

    return S2N_RESULT_OK;
}

int s2n_test_kem_with_kat(const struct s2n_kem *kem, const char *kat_file_name) {
    S2N_ERROR_IF(s2n_is_in_fips_mode(), S2N_ERR_PQ_KEMS_DISALLOWED_IN_FIPS);
    ENSURE_POSIX(s2n_in_unit_test(), S2N_ERR_NOT_IN_UNIT_TEST);

    notnull_check(kem);

    FILE *kat_file = fopen(kat_file_name, "r");
    notnull_check(kat_file);

    uint8_t *ct, *client_shared_secret, *pk, *sk, *server_shared_secret, *pk_answer, *sk_answer, *ct_answer, *ss_answer;
    /* Client side variables */
    notnull_check(ct = malloc(kem->ciphertext_length));
    notnull_check(client_shared_secret = malloc(kem->shared_secret_key_length));

    /* Server side variables */
    notnull_check(pk = malloc(kem->public_key_length));
    notnull_check(sk = malloc(kem->private_key_length));
    notnull_check(server_shared_secret = malloc(kem->shared_secret_key_length));

    /* Known answer variables */
    notnull_check(pk_answer = malloc(kem->public_key_length));
    notnull_check(sk_answer = malloc(kem->private_key_length));
    notnull_check(ct_answer = malloc(kem->ciphertext_length));
    notnull_check(ss_answer = malloc(kem->shared_secret_key_length));

    s2n_stack_blob(personalization_string, SEED_LENGTH, SEED_LENGTH);
    GUARD(s2n_rand_set_callbacks(s2n_pq_kat_rand_init, s2n_pq_kat_rand_cleanup, s2n_pq_kat_seed_entropy,
            s2n_pq_kat_mix_entropy));
    GUARD_AS_POSIX(s2n_set_rand_bytes_callback_for_testing(s2n_get_random_bytes_for_pq_kat_tests));

    for (size_t i = 0; i < NUM_OF_KATS; i++) {
        /* Verify test index */
        int32_t count = 0;
        GUARD(FindMarker(kat_file, "count = "));
        gt_check(fscanf(kat_file, "%d", &count), 0);
        eq_check(count, i);

        /* Set the DRBG to the state that was used to generate this test vector. We instantiate the DRBG
         * as S2N_AES_256_CTR_NO_DF_PR; since the NIST KATs were generated without prediction resistance,
         * we use the custom function s2n_drbg_generate_for_pq_kat_tests() defined above to turn off the
         * prediction resistance. */
        GUARD(ReadHex(kat_file, kat_entropy_blob.data, SEED_LENGTH, "seed = "));
        GUARD(s2n_drbg_instantiate(&drbg_for_pq_kats, &personalization_string, S2N_AES_256_CTR_NO_DF_PR));

        /* Generate the public/private key pair */
        GUARD(kem->generate_keypair(pk, sk));

        /* Create a shared secret and use the public key to encrypt it */
        GUARD(kem->encapsulate(ct, client_shared_secret, pk));

        /* Use the private key to decrypt the ct to get the shared secret */
        GUARD(kem->decapsulate(server_shared_secret, ct, sk));

        /* Read the KAT values */
        GUARD(ReadHex(kat_file, pk_answer, kem->public_key_length, "pk = "));
        GUARD(ReadHex(kat_file, sk_answer, kem->private_key_length, "sk = "));
        GUARD(ReadHex(kat_file, ct_answer, kem->ciphertext_length, "ct = "));
        GUARD(ReadHex(kat_file, ss_answer, kem->shared_secret_key_length, "ss = "));

        /* Test the client and server got the same value */
        eq_check(memcmp(client_shared_secret, server_shared_secret, kem->shared_secret_key_length), 0);

        /* Compare the KAT values */
        eq_check(memcmp(pk_answer, pk, kem->public_key_length), 0);
        eq_check(memcmp(sk_answer, sk, kem->private_key_length), 0);
        eq_check(memcmp(ct_answer, ct, kem->ciphertext_length), 0);
        eq_check(memcmp(ss_answer, server_shared_secret, kem->shared_secret_key_length ), 0);

        /* Wipe the DRBG; it will reseed for each KAT test vector. */
        GUARD(s2n_drbg_wipe(&drbg_for_pq_kats));
    }
    fclose(kat_file);
    free(ct);
    free(client_shared_secret);
    free(pk);
    free(sk);
    free(server_shared_secret);
    free(pk_answer);
    free(sk_answer);
    free(ct_answer);
    free(ss_answer);

    return 0;
}
