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

#include "crypto/s2n_hash.h"
#include "s2n_test.h"
#include "testlib/s2n_testlib.h"

int main(int argc, char **argv)
{
    BEGIN_TEST();

    /* Test: s2n_hash_new_raw */
    {
        /* Test: matches s2n_hash_new, minus hash_impl */
        {
            struct s2n_blob buffer = { 0 };
            DEFER_CLEANUP(struct s2n_hash_state raw_state = { 0 }, s2n_hash_free);
            EXPECT_OK(s2n_hash_new_raw(&raw_state, &buffer));

            DEFER_CLEANUP(struct s2n_hash_state hash_state = { 0 }, s2n_hash_free);
            EXPECT_SUCCESS(s2n_hash_new(&hash_state));

            EXPECT_EQUAL(raw_state.alg, hash_state.alg);
            EXPECT_EQUAL(raw_state.currently_in_hash, hash_state.currently_in_hash);
            EXPECT_EQUAL(raw_state.is_ready_for_input, hash_state.is_ready_for_input);

            EXPECT_NOT_EQUAL(raw_state.hash_impl, hash_state.hash_impl);
            EXPECT_EQUAL(s2n_hash_get_type(&raw_state), S2N_HASH_TYPE_RAW);
        };

        /* Test: properly configure the raw data buffer */
        {
            uint8_t buffer_bytes[10] = { 0 };
            struct s2n_blob buffer = { 0 };
            EXPECT_SUCCESS(s2n_blob_init(&buffer, buffer_bytes, sizeof(buffer_bytes)));

            DEFER_CLEANUP(struct s2n_hash_state raw_state = { 0 }, s2n_hash_free);
            EXPECT_OK(s2n_hash_new_raw(&raw_state, &buffer));

            struct s2n_stuffer *raw_data = &raw_state.digest.raw_data;
            EXPECT_EQUAL(raw_data->blob.size, buffer.size);
            EXPECT_EQUAL(raw_data->blob.data, buffer.data);
            EXPECT_EQUAL(s2n_stuffer_data_available(raw_data), 0);
            EXPECT_EQUAL(s2n_stuffer_space_remaining(raw_data), buffer.size);
        };
    };

    /* Test: s2n_hash_init */
    {
        for (s2n_hash_algorithm hash_alg = 0; hash_alg < S2N_HASH_ALGS_COUNT; hash_alg++) {
            struct s2n_blob buffer = { 0 };
            DEFER_CLEANUP(struct s2n_hash_state raw_state = { 0 }, s2n_hash_free);
            EXPECT_OK(s2n_hash_new_raw(&raw_state, &buffer));
            EXPECT_SUCCESS(s2n_hash_init(&raw_state, hash_alg));

            EXPECT_EQUAL(raw_state.alg, hash_alg);
            EXPECT_EQUAL(raw_state.is_ready_for_input, 1);
            EXPECT_EQUAL(raw_state.currently_in_hash, 0);
        }
    };

    /* Test: s2n_hash_update */
    {
        uint8_t test_data[] = "this is some test data";
        uint8_t write_sizes[] = { 5, 3, 5, 5, 5 };

        /* Test: single update */
        {
            uint8_t buffer_bytes[sizeof(test_data)] = { 0 };
            struct s2n_blob buffer = { 0 };
            EXPECT_SUCCESS(s2n_blob_init(&buffer, buffer_bytes, sizeof(buffer_bytes)));

            DEFER_CLEANUP(struct s2n_hash_state raw_state = { 0 }, s2n_hash_free);
            EXPECT_OK(s2n_hash_new_raw(&raw_state, &buffer));
            EXPECT_SUCCESS(s2n_hash_init(&raw_state, S2N_HASH_SHA256));

            EXPECT_SUCCESS(s2n_hash_update(&raw_state, test_data, sizeof(test_data)));

            struct s2n_stuffer *raw_data = &raw_state.digest.raw_data;
            EXPECT_EQUAL(raw_state.currently_in_hash, sizeof(test_data));
            EXPECT_EQUAL(s2n_stuffer_data_available(raw_data), sizeof(test_data));
            EXPECT_BYTEARRAY_EQUAL(test_data, buffer_bytes, sizeof(test_data));
        };

        /* Test: multiple updates */
        {
            uint8_t buffer_bytes[sizeof(test_data)] = { 0 };
            struct s2n_blob buffer = { 0 };
            EXPECT_SUCCESS(s2n_blob_init(&buffer, buffer_bytes, sizeof(buffer_bytes)));

            DEFER_CLEANUP(struct s2n_hash_state raw_state = { 0 }, s2n_hash_free);
            EXPECT_OK(s2n_hash_new_raw(&raw_state, &buffer));
            EXPECT_SUCCESS(s2n_hash_init(&raw_state, S2N_HASH_SHA384));

            size_t written = 0;
            for (size_t i = 0; i < s2n_array_len(write_sizes); i++) {
                EXPECT_SUCCESS(s2n_hash_update(&raw_state, test_data + written,
                        write_sizes[i]));
                written += write_sizes[i];
            }

            struct s2n_stuffer *raw_data = &raw_state.digest.raw_data;
            EXPECT_EQUAL(raw_state.currently_in_hash, sizeof(test_data));
            EXPECT_EQUAL(s2n_stuffer_data_available(raw_data), sizeof(test_data));
            EXPECT_BYTEARRAY_EQUAL(test_data, buffer_bytes, sizeof(test_data));
        };

        /* Test: update too large for buffer */
        {
            /* Configure the buffer smaller than the test data */
            uint8_t buffer_bytes[sizeof(test_data) / 2] = { 0 };
            struct s2n_blob buffer = { 0 };
            EXPECT_SUCCESS(s2n_blob_init(&buffer, buffer_bytes, sizeof(buffer_bytes)));

            DEFER_CLEANUP(struct s2n_hash_state raw_state = { 0 }, s2n_hash_free);
            EXPECT_OK(s2n_hash_new_raw(&raw_state, &buffer));
            EXPECT_SUCCESS(s2n_hash_init(&raw_state, S2N_HASH_SHA512));

            EXPECT_FAILURE_WITH_ERRNO(s2n_hash_update(&raw_state, test_data, sizeof(test_data)),
                    S2N_ERR_STUFFER_IS_FULL);
        };
    };

    /* Test: s2n_hash_digest */
    {
        uint8_t test_data[] = "this is some test data";

        uint8_t buffer_bytes[sizeof(test_data)] = { 0 };
        struct s2n_blob buffer = { 0 };
        EXPECT_SUCCESS(s2n_blob_init(&buffer, buffer_bytes, sizeof(buffer_bytes)));

        DEFER_CLEANUP(struct s2n_hash_state raw_state = { 0 }, s2n_hash_free);
        EXPECT_OK(s2n_hash_new_raw(&raw_state, &buffer));
        EXPECT_SUCCESS(s2n_hash_init(&raw_state, S2N_HASH_SHA384));
        EXPECT_SUCCESS(s2n_hash_update(&raw_state, test_data, sizeof(test_data)));
        EXPECT_EQUAL(raw_state.is_ready_for_input, 1);

        /* Test: Too little data requested */
        {
            uint8_t result_data[sizeof(test_data)] = { 0 };
            EXPECT_FAILURE_WITH_ERRNO(s2n_hash_digest(&raw_state, result_data, 1),
                    S2N_ERR_SAFETY);
            EXPECT_EQUAL(raw_state.is_ready_for_input, 1);
        }

        /* Test: Too much data requested */
        {
            uint8_t result_data[sizeof(test_data)] = { 0 };
            EXPECT_FAILURE_WITH_ERRNO(s2n_hash_digest(&raw_state, result_data, sizeof(test_data) * 2),
                    S2N_ERR_SAFETY);
            EXPECT_EQUAL(raw_state.is_ready_for_input, 1);
        }

        /* Test: Correct digest size requested */
        {
            uint8_t result_data[sizeof(test_data)] = { 0 };
            EXPECT_SUCCESS(s2n_hash_digest(&raw_state, result_data, sizeof(result_data)));
            EXPECT_EQUAL(raw_state.is_ready_for_input, 0);
            EXPECT_EQUAL(raw_state.currently_in_hash, 0);

            /* Despite the name, s2n_hash_digest just returns the raw test data */
            EXPECT_BYTEARRAY_EQUAL(result_data, test_data, sizeof(test_data));
        }

        /* Test: Cannot digest again */
        {
            uint8_t result_data[sizeof(test_data)] = { 0 };
            EXPECT_FAILURE_WITH_ERRNO(s2n_hash_digest(&raw_state, result_data, sizeof(result_data)),
                    S2N_ERR_HASH_NOT_READY);
        }
    };

    /* Test: s2n_hash_new_copy */
    {
        uint8_t test_data[] = "data for copying";

        uint8_t buffer_bytes[sizeof(test_data)] = { 0 };
        struct s2n_blob buffer = { 0 };
        EXPECT_SUCCESS(s2n_blob_init(&buffer, buffer_bytes, sizeof(buffer_bytes)));

        DEFER_CLEANUP(struct s2n_hash_state raw_state = { 0 }, s2n_hash_free);
        EXPECT_OK(s2n_hash_new_raw(&raw_state, &buffer));
        EXPECT_SUCCESS(s2n_hash_init(&raw_state, S2N_HASH_SHA256));
        EXPECT_SUCCESS(s2n_hash_update(&raw_state, test_data, sizeof(test_data)));

        DEFER_CLEANUP(struct s2n_hash_state copy_state = { 0 }, s2n_hash_free);
        EXPECT_OK(s2n_hash_new_copy(&copy_state, &raw_state));

        /* Copy fields match original fields */
        EXPECT_EQUAL(raw_state.alg, copy_state.alg);
        EXPECT_EQUAL(raw_state.currently_in_hash, copy_state.currently_in_hash);
        EXPECT_EQUAL(raw_state.is_ready_for_input, copy_state.is_ready_for_input);
        EXPECT_EQUAL(raw_state.hash_impl, copy_state.hash_impl);

        /* Stuffer data in copy matches original */
        EXPECT_EQUAL(s2n_stuffer_data_available(&raw_state.digest.raw_data),
                s2n_stuffer_data_available(&copy_state.digest.raw_data));
        EXPECT_BYTEARRAY_EQUAL(raw_state.digest.raw_data.blob.data, test_data, sizeof(test_data));
        EXPECT_BYTEARRAY_EQUAL(copy_state.digest.raw_data.blob.data, test_data, sizeof(test_data));

        /* Both digests can be calculated separately */
        uint8_t original_result[sizeof(test_data)] = { 0 };
        uint8_t copy_result[sizeof(test_data)] = { 0 };
        EXPECT_SUCCESS(s2n_hash_digest(&raw_state, original_result, sizeof(original_result)));
        EXPECT_SUCCESS(s2n_hash_digest(&copy_state, copy_result, sizeof(copy_result)));
        EXPECT_BYTEARRAY_EQUAL(original_result, test_data, sizeof(test_data));
        EXPECT_BYTEARRAY_EQUAL(copy_result, test_data, sizeof(test_data));
    };

    /* Test: s2n_hash_reset */
    {
        uint8_t test_data[] = "data for reseting";

        uint8_t buffer_bytes[sizeof(test_data)] = { 0 };
        struct s2n_blob buffer = { 0 };
        EXPECT_SUCCESS(s2n_blob_init(&buffer, buffer_bytes, sizeof(buffer_bytes)));

        DEFER_CLEANUP(struct s2n_hash_state raw_state = { 0 }, s2n_hash_free);
        EXPECT_OK(s2n_hash_new_raw(&raw_state, &buffer));
        EXPECT_SUCCESS(s2n_hash_init(&raw_state, S2N_HASH_SHA256));
        EXPECT_SUCCESS(s2n_hash_update(&raw_state, test_data, sizeof(test_data)));

        struct s2n_stuffer *raw_data = &raw_state.digest.raw_data;

        EXPECT_NOT_EQUAL(s2n_stuffer_data_available(raw_data), 0);
        EXPECT_EQUAL(s2n_hash_get_type(&raw_state), S2N_HASH_TYPE_RAW);

        EXPECT_SUCCESS(s2n_hash_reset(&raw_state));

        EXPECT_EQUAL(s2n_stuffer_data_available(raw_data), 0);
        EXPECT_EQUAL(s2n_hash_get_type(&raw_state), S2N_HASH_TYPE_RAW);
    };

    END_TEST();
}
