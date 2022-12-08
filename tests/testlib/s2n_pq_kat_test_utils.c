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

#include "pq-crypto/s2n_pq.h"
#include "pq-crypto/s2n_pq_random.h"
#include "testlib/s2n_nist_kats.h"
#include "testlib/s2n_testlib.h"
#include "tls/s2n_kem.h"
#include "utils/s2n_mem.h"
#include "utils/s2n_safety.h"

/* We include s2n_drbg.c directly in order to access the static functions in our entropy callbacks. */
#include "crypto/s2n_drbg.c"

#define SEED_LENGTH 48
uint8_t kat_entropy_buff[SEED_LENGTH] = { 0 };
struct s2n_blob kat_entropy_blob = { .size = SEED_LENGTH, .data = kat_entropy_buff };
struct s2n_drbg drbg_for_pq_kats;

int s2n_pq_kat_rand_init(void)
{
    POSIX_ENSURE(s2n_in_unit_test(), S2N_ERR_NOT_IN_UNIT_TEST);
    return S2N_SUCCESS;
}

int s2n_pq_kat_rand_cleanup(void)
{
    return S2N_SUCCESS;
}

/* The seed entropy is taken from the NIST KAT file. */
int s2n_pq_kat_seed_entropy(void *ptr, uint32_t size)
{
    POSIX_ENSURE(s2n_in_unit_test(), S2N_ERR_NOT_IN_UNIT_TEST);
    POSIX_ENSURE_REF(ptr);
    POSIX_ENSURE_EQ(size, kat_entropy_blob.size);
    POSIX_CHECKED_MEMCPY(ptr, kat_entropy_buff, size);

    return S2N_SUCCESS;
}

/* Since the NIST KATs were generated without prediction resistance, the
 * mix entropy callback should never be called. */
static int s2n_pq_kat_mix_entropy(void *ptr, uint32_t size)
{
    return S2N_FAILURE;
}

/* Adapted from s2n_drbg.c::s2n_drbg_generate(); this allows us to side-step the DRBG
 * prediction resistance that is built in to s2n's DRBG modes. The PQ KATs were generated
 * using AES 256 CTR NO DF NO PR. */
static S2N_RESULT s2n_drbg_generate_for_pq_kat_tests(struct s2n_drbg *drbg, struct s2n_blob *blob)
{
    RESULT_ENSURE(s2n_in_unit_test(), S2N_ERR_NOT_IN_UNIT_TEST);
    RESULT_ENSURE_REF(drbg);
    RESULT_ENSURE_REF(drbg->ctx);
    uint8_t zeros_buffer[S2N_DRBG_MAX_SEED_SIZE] = { 0 };
    struct s2n_blob zeros = { .data = zeros_buffer, .size = s2n_drbg_seed_size(drbg) };

    RESULT_ENSURE(blob->size <= S2N_DRBG_GENERATE_LIMIT, S2N_ERR_DRBG_REQUEST_SIZE);

    /* We do NOT mix in additional entropy */
    RESULT_GUARD(s2n_drbg_bits(drbg, blob));
    RESULT_GUARD(s2n_drbg_update(drbg, &zeros));

    return S2N_RESULT_OK;
}

/* Adapted from s2n_random.c::s2n_get_private_random_data(). */
static S2N_RESULT s2n_get_random_data_for_pq_kat_tests(struct s2n_blob *blob)
{
    RESULT_ENSURE(s2n_in_unit_test(), S2N_ERR_NOT_IN_UNIT_TEST);
    uint32_t offset = 0;
    uint32_t remaining = blob->size;

    while (remaining) {
        struct s2n_blob slice = { 0 };

        RESULT_GUARD_POSIX(s2n_blob_slice(blob, &slice, offset, MIN(remaining, S2N_DRBG_GENERATE_LIMIT)));
        RESULT_GUARD(s2n_drbg_generate_for_pq_kat_tests(&drbg_for_pq_kats, &slice));

        remaining -= slice.size;
        offset += slice.size;
    }

    return S2N_RESULT_OK;
}

S2N_RESULT s2n_get_random_bytes_for_pq_kat_tests(uint8_t *buffer, uint32_t num_bytes)
{
    RESULT_ENSURE(s2n_in_unit_test(), S2N_ERR_NOT_IN_UNIT_TEST);
    struct s2n_blob out = { .data = buffer, .size = num_bytes };

    RESULT_GUARD(s2n_get_random_data_for_pq_kat_tests(&out));

    return S2N_RESULT_OK;
}

static int s2n_test_kem_with_kat(const struct s2n_kem *kem, const char *kat_file_name)
{
    POSIX_ENSURE(s2n_pq_is_enabled(), S2N_ERR_PQ_DISABLED);
    POSIX_ENSURE(s2n_in_unit_test(), S2N_ERR_NOT_IN_UNIT_TEST);

    POSIX_ENSURE_REF(kem);

    FILE *kat_file = fopen(kat_file_name, "r");
    POSIX_ENSURE_REF(kat_file);

    uint8_t *ct, *client_shared_secret, *pk, *sk, *server_shared_secret, *pk_answer, *sk_answer, *ct_answer, *ss_answer;
    /* Client side variables */
    POSIX_ENSURE_REF(ct = malloc(kem->ciphertext_length));
    POSIX_ENSURE_REF(client_shared_secret = malloc(kem->shared_secret_key_length));

    /* Server side variables */
    POSIX_ENSURE_REF(pk = malloc(kem->public_key_length));
    POSIX_ENSURE_REF(sk = malloc(kem->private_key_length));
    POSIX_ENSURE_REF(server_shared_secret = malloc(kem->shared_secret_key_length));

    /* Known answer variables */
    POSIX_ENSURE_REF(pk_answer = malloc(kem->public_key_length));
    POSIX_ENSURE_REF(sk_answer = malloc(kem->private_key_length));
    POSIX_ENSURE_REF(ct_answer = malloc(kem->ciphertext_length));
    POSIX_ENSURE_REF(ss_answer = malloc(kem->shared_secret_key_length));

    s2n_stack_blob(personalization_string, SEED_LENGTH, SEED_LENGTH);
    POSIX_GUARD(s2n_rand_set_callbacks(s2n_pq_kat_rand_init, s2n_pq_kat_rand_cleanup, s2n_pq_kat_seed_entropy,
            s2n_pq_kat_mix_entropy));
    POSIX_GUARD_RESULT(s2n_set_rand_bytes_callback_for_testing(s2n_get_random_bytes_for_pq_kat_tests));

    for (size_t i = 0; i < NUM_OF_KATS; i++) {
        /* Verify test index */
        int32_t count = 0;
        POSIX_GUARD(FindMarker(kat_file, "count = "));
        POSIX_ENSURE_GT(fscanf(kat_file, "%d", &count), 0);
        POSIX_ENSURE_EQ(count, i);

        /* Set the DRBG to the state that was used to generate this test vector. We instantiate the DRBG
         * as S2N_AES_256_CTR_NO_DF_PR; since the NIST KATs were generated without prediction resistance,
         * we use the custom function s2n_drbg_generate_for_pq_kat_tests() defined above to turn off the
         * prediction resistance. */
        POSIX_GUARD(ReadHex(kat_file, kat_entropy_blob.data, SEED_LENGTH, "seed = "));
        POSIX_GUARD_RESULT(s2n_drbg_instantiate(&drbg_for_pq_kats, &personalization_string, S2N_AES_256_CTR_NO_DF_PR));

        /* Generate the public/private key pair */
        POSIX_GUARD(kem->generate_keypair(pk, sk));

        /* Create a shared secret and use the public key to encrypt it */
        POSIX_GUARD(kem->encapsulate(ct, client_shared_secret, pk));

        /* Use the private key to decrypt the ct to get the shared secret */
        POSIX_GUARD(kem->decapsulate(server_shared_secret, ct, sk));

        /* Read the KAT values */
        POSIX_GUARD(ReadHex(kat_file, pk_answer, kem->public_key_length, "pk = "));
        POSIX_GUARD(ReadHex(kat_file, sk_answer, kem->private_key_length, "sk = "));
        POSIX_GUARD(ReadHex(kat_file, ct_answer, kem->ciphertext_length, "ct = "));
        POSIX_GUARD(ReadHex(kat_file, ss_answer, kem->shared_secret_key_length, "ss = "));

        /* Test the client and server got the same value */
        POSIX_ENSURE_EQ(memcmp(client_shared_secret, server_shared_secret, kem->shared_secret_key_length), 0);

        /* Compare the KAT values */
        POSIX_ENSURE_EQ(memcmp(pk_answer, pk, kem->public_key_length), 0);
        POSIX_ENSURE_EQ(memcmp(sk_answer, sk, kem->private_key_length), 0);
        POSIX_ENSURE_EQ(memcmp(ct_answer, ct, kem->ciphertext_length), 0);
        POSIX_ENSURE_EQ(memcmp(ss_answer, server_shared_secret, kem->shared_secret_key_length), 0);

        /* Wipe the DRBG; it will reseed for each KAT test vector. */
        POSIX_GUARD_RESULT(s2n_drbg_wipe(&drbg_for_pq_kats));
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

S2N_RESULT s2n_pq_kem_kat_test(const struct s2n_kem_kat_test_vector *test_vectors, size_t count)
{
    RESULT_ENSURE_GT(count, 0);
    for (size_t i = 0; i < count; i++) {
        const struct s2n_kem_kat_test_vector vector = test_vectors[i];
        const struct s2n_kem *kem = vector.kem;

        /* Test the C code */
        RESULT_GUARD(vector.disable_asm());
        RESULT_GUARD_POSIX(s2n_test_kem_with_kat(kem, vector.kat_file));

        /* Test the assembly, if available */
        RESULT_GUARD(vector.enable_asm());
        if (vector.asm_is_enabled()) {
            RESULT_GUARD_POSIX(s2n_test_kem_with_kat(kem, vector.kat_file));
        }
    }
    return S2N_RESULT_OK;
}

S2N_RESULT s2n_pq_noop_asm()
{
    return S2N_RESULT_OK;
}

bool s2n_pq_no_asm_available()
{
    return false;
}
