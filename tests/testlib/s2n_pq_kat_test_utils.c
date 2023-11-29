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

#include "crypto/s2n_pq.h"
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

/* Adapted from s2n_drbg.c::s2n_drbg_generate(); this allows us to side-step the DRBG
 * prediction resistance that is built in to s2n's DRBG modes. The PQ KATs were generated
 * using AES 256 CTR NO DF NO PR. */
static S2N_RESULT s2n_drbg_generate_for_pq_kat_tests(struct s2n_drbg *drbg, struct s2n_blob *blob)
{
    RESULT_ENSURE(s2n_in_unit_test(), S2N_ERR_NOT_IN_UNIT_TEST);
    RESULT_ENSURE_REF(drbg);
    RESULT_ENSURE_REF(drbg->ctx);
    uint8_t zeros_buffer[S2N_DRBG_MAX_SEED_SIZE] = { 0 };
    struct s2n_blob zeros = { 0 };
    RESULT_GUARD_POSIX(s2n_blob_init(&zeros, zeros_buffer, s2n_drbg_seed_size(drbg)));

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
    struct s2n_blob out = { 0 };
    RESULT_GUARD_POSIX(s2n_blob_init(&out, buffer, num_bytes));

    RESULT_GUARD(s2n_get_random_data_for_pq_kat_tests(&out));

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
