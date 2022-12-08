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

#include "crypto/s2n_evp.h"
#include "crypto/s2n_fips.h"
#include "crypto/s2n_hash.h"
#include "s2n_test.h"
#include "testlib/s2n_testlib.h"

#define INPUT_DATA_SIZE  100
#define OUTPUT_DATA_SIZE 100

const uint8_t input_data[INPUT_DATA_SIZE] = "hello hash";

/* These values were generated using the low level s2n_hash implementation.
 * They are useful to validate that the results of the low level implementation
 * never change and match the results of the EVP implementation.
 */
const char *expected_result_hex[S2N_HASH_SENTINEL] = {
    [S2N_HASH_NONE] = "",
    [S2N_HASH_MD5] = "f5d589043253ca6ae54124c31be43701",
    [S2N_HASH_SHA1] = "ccf8abd6b03ef5054a4f257e7c712e17f965272d",
    [S2N_HASH_SHA224] = "dae80554ab74bf098b1a39e48c85c58e4af4628d2a357ee5cf6b1b85",
    [S2N_HASH_SHA256] = "a8a7fb9d2d3ff62eee5bed1bfcc7b2e17ffebf00c3c77fdf43259d690022041f",
    [S2N_HASH_SHA384] = "d7131b24ea0985fc9f6462139969decff21f24967f6df17e31ce2410fda6534a5c"
                        "f85cb4be737961eddce0c201c0dac0",
    [S2N_HASH_SHA512] = "b11305336d6071d8cbab6709fc1019f874961e13a04611f8e7d4c1f9164a2c923f"
                        "7b3da0a37001cef5fdb71584a0f92020a45f23a6fc06cc3ab42ceaa0467a34",
    [S2N_HASH_MD5_SHA1] = "f5d589043253ca6ae54124c31be43701ccf8abd6b03ef5054a4f257e7c712e17f965272d",
};

S2N_RESULT s2n_hash_test_state(struct s2n_hash_state *hash_state, s2n_hash_algorithm hash_alg, struct s2n_blob *digest)
{
    /* Test s2n_hash_update */
    {
        /* Break the test data into some arbitrarily sized chunks. */
        size_t chunk_sizes[] = { 1, 0, 10, 17, 31 };

        size_t offset = 0;
        for (size_t i = 0; i < s2n_array_len(chunk_sizes); i++) {
            RESULT_GUARD_POSIX(s2n_hash_update(hash_state, input_data + offset, chunk_sizes[i]));
            offset += chunk_sizes[i];
            RESULT_ENSURE_EQ(hash_state->currently_in_hash, offset);
        }

        /* Add the rest */
        RESULT_GUARD_POSIX(s2n_hash_update(hash_state, input_data + offset, (INPUT_DATA_SIZE - offset)));
        RESULT_ENSURE_EQ(hash_state->currently_in_hash, INPUT_DATA_SIZE);
    };

    /* Test s2n_hash_copy */
    struct s2n_hash_state hash_copy = { 0 };
    {
        struct s2n_blob result = { 0 };
        uint8_t result_data[OUTPUT_DATA_SIZE] = { 0 };
        RESULT_GUARD_POSIX(s2n_blob_init(&result, result_data, OUTPUT_DATA_SIZE));

        RESULT_GUARD_POSIX(s2n_hash_new(&hash_copy));
        RESULT_GUARD_POSIX(s2n_hash_copy(&hash_copy, hash_state));
        RESULT_ENSURE_EQ(hash_copy.currently_in_hash, hash_state->currently_in_hash);
        RESULT_ENSURE_EQ(hash_copy.is_ready_for_input, hash_state->is_ready_for_input);
    };

    /* Test s2n_hash_digest */
    {
        uint8_t digest_size = 0;
        RESULT_GUARD_POSIX(s2n_hash_digest_size(hash_alg, &digest_size));
        digest->size = digest_size;

        RESULT_GUARD_POSIX(s2n_hash_digest(hash_state, digest->data, digest_size));
        RESULT_ENSURE_EQ(hash_state->currently_in_hash, 0);
        RESULT_ENSURE_EQ(hash_state->is_ready_for_input, false);

        uint8_t copy_result[OUTPUT_DATA_SIZE] = { 0 };
        RESULT_GUARD_POSIX(s2n_hash_digest(&hash_copy, copy_result, digest_size));
        RESULT_ENSURE_EQ(hash_state->currently_in_hash, 0);
        RESULT_ENSURE_EQ(hash_state->is_ready_for_input, false);
        RESULT_ENSURE_EQ(memcmp(digest->data, copy_result, digest_size), 0);
    };

    RESULT_GUARD_POSIX(s2n_hash_free(&hash_copy));
    return S2N_RESULT_OK;
}

S2N_RESULT s2n_hash_test(s2n_hash_algorithm hash_alg, struct s2n_blob *digest)
{
    struct s2n_hash_state hash_state = { 0 };

    /* Test s2n_hash_new + s2n_hash_init */
    {
        RESULT_GUARD_POSIX(s2n_hash_new(&hash_state));
        RESULT_ENSURE_EQ(hash_state.currently_in_hash, 0);
        RESULT_ENSURE_EQ(hash_state.is_ready_for_input, false);

        /* Allow MD5 when necessary */
        if (s2n_is_in_fips_mode() && (hash_alg == S2N_HASH_MD5 || hash_alg == S2N_HASH_MD5_SHA1)) {
            RESULT_GUARD_POSIX(s2n_hash_allow_md5_for_fips(&hash_state));
        }

        RESULT_GUARD_POSIX(s2n_hash_init(&hash_state, hash_alg));
        RESULT_ENSURE_EQ(hash_state.currently_in_hash, 0);
        RESULT_ENSURE_EQ(hash_state.is_ready_for_input, true);

        RESULT_GUARD(s2n_hash_test_state(&hash_state, hash_alg, digest));
    };

    /* Test s2n_hash_reset */
    {
        struct s2n_blob result = { 0 };
        uint8_t result_data[OUTPUT_DATA_SIZE] = { 0 };
        RESULT_GUARD_POSIX(s2n_blob_init(&result, result_data, OUTPUT_DATA_SIZE));

        RESULT_GUARD_POSIX(s2n_hash_reset(&hash_state));
        RESULT_ENSURE_EQ(hash_state.currently_in_hash, 0);
        RESULT_ENSURE_EQ(hash_state.is_ready_for_input, true);

        RESULT_GUARD(s2n_hash_test_state(&hash_state, hash_alg, &result));
        RESULT_ENSURE_EQ(digest->size, result.size);
        RESULT_ENSURE_EQ(memcmp(digest->data, result.data, result.size), 0);
    };

    RESULT_GUARD_POSIX(s2n_hash_free(&hash_state));
    return S2N_RESULT_OK;
}

int main(int argc, char **argv)
{
    BEGIN_TEST();

    /* Calculate digests when not in FIPS mode. They must match. */
    for (s2n_hash_algorithm hash_alg = 0; hash_alg < S2N_HASH_SENTINEL; hash_alg++) {
        struct s2n_blob actual_result = { 0 };
        uint8_t actual_result_data[OUTPUT_DATA_SIZE] = { 0 };
        EXPECT_SUCCESS(s2n_blob_init(&actual_result, actual_result_data, OUTPUT_DATA_SIZE));

        struct s2n_blob expected_result = { 0 };
        uint8_t expected_result_data[OUTPUT_DATA_SIZE] = { 0 };
        EXPECT_SUCCESS(s2n_blob_init(&expected_result, expected_result_data, OUTPUT_DATA_SIZE));
        EXPECT_SUCCESS(s2n_hex_string_to_bytes((const uint8_t *) expected_result_hex[hash_alg], &expected_result));

        EXPECT_OK(s2n_hash_test(hash_alg, &actual_result));
        EXPECT_EQUAL(expected_result.size, actual_result.size);
        EXPECT_BYTEARRAY_EQUAL(expected_result.data, actual_result.data, actual_result.size);
    }

    END_TEST();
}
