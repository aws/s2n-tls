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

#include "tls/s2n_fingerprint.h"

#include "crypto/s2n_hash.h"
#include "s2n_test.h"
#include "testlib/s2n_testlib.h"

#define S2N_TEST_HASH S2N_HASH_SHA256
#define TEST_COUNT    10

static S2N_RESULT s2n_test_hash_state_new(struct s2n_hash_state *hash_state)
{
    EXPECT_SUCCESS(s2n_hash_new(hash_state));
    EXPECT_SUCCESS(s2n_hash_init(hash_state, S2N_TEST_HASH));
    return S2N_RESULT_OK;
}

int main(int argc, char **argv)
{
    BEGIN_TEST();

    const char test_char = '!';
    const char test_str[] = "hello";
    const size_t test_str_len = strlen(test_str);
    EXPECT_NOT_EQUAL(test_char, test_str[0]);

    const uint8_t test_str_digest[] = {
        0x2c, 0xf2, 0x4d, 0xba, 0x5f, 0xb0, 0xa3, 0xe, 0x26, 0xe8, 0x3b,
        0x2a, 0xc5, 0xb9, 0xe2, 0x9e, 0x1b, 0x16, 0x1e, 0x5c, 0x1f, 0xa7,
        0x42, 0x5e, 0x73, 0x4, 0x33, 0x62, 0x93, 0x8b, 0x98, 0x24
    };

    /* Test s2n_fingerprint_hash_add_char */
    {
        /* Safety */
        EXPECT_ERROR_WITH_ERRNO(s2n_fingerprint_hash_add_char(NULL, test_char),
                S2N_ERR_NULL);

        /* Add to stuffer */
        {
            DEFER_CLEANUP(struct s2n_stuffer output = { 0 }, s2n_stuffer_free);
            EXPECT_SUCCESS(s2n_stuffer_alloc(&output, TEST_COUNT));
            struct s2n_fingerprint_hash hash = { .buffer = &output };

            for (size_t i = 1; i <= TEST_COUNT; i++) {
                EXPECT_OK(s2n_fingerprint_hash_add_char(&hash, test_char));
                EXPECT_EQUAL(s2n_stuffer_data_available(&output), 1);

                char actual_value = 0;
                EXPECT_SUCCESS(s2n_stuffer_read_char(&output, &actual_value));
                EXPECT_EQUAL(actual_value, test_char);
            }
        };

        /* Add to hash */
        {
            DEFER_CLEANUP(struct s2n_hash_state hash_state = { 0 }, s2n_hash_free);
            EXPECT_OK(s2n_test_hash_state_new(&hash_state));
            struct s2n_fingerprint_hash hash = { .hash = &hash_state };

            for (size_t i = 1; i <= TEST_COUNT; i++) {
                EXPECT_OK(s2n_fingerprint_hash_add_char(&hash, test_char));
                EXPECT_EQUAL(hash.hash->currently_in_hash, i);
            }
        };

        /* Error due to insufficient space */
        {
            DEFER_CLEANUP(struct s2n_stuffer output = { 0 }, s2n_stuffer_free);
            struct s2n_fingerprint_hash hash = { .buffer = &output };
            EXPECT_ERROR_WITH_ERRNO(s2n_fingerprint_hash_add_char(&hash, test_char),
                    S2N_ERR_INSUFFICIENT_MEM_SIZE);

            EXPECT_SUCCESS(s2n_stuffer_alloc(&output, 1));
            EXPECT_OK(s2n_fingerprint_hash_add_char(&hash, test_char));
            EXPECT_ERROR_WITH_ERRNO(s2n_fingerprint_hash_add_char(&hash, test_char),
                    S2N_ERR_INSUFFICIENT_MEM_SIZE);
        };
    };

    /* Test s2n_fingerprint_hash_add_str */
    {
        /* Safety */
        {
            /* Null hash */
            EXPECT_ERROR_WITH_ERRNO(s2n_fingerprint_hash_add_str(NULL, test_str, 0),
                    S2N_ERR_NULL);

            /* Null str with stuffer */
            {
                DEFER_CLEANUP(struct s2n_stuffer output = { 0 }, s2n_stuffer_free);
                EXPECT_SUCCESS(s2n_stuffer_alloc(&output, 100));
                struct s2n_fingerprint_hash hash = { .buffer = &output };
                EXPECT_ERROR_WITH_ERRNO(s2n_fingerprint_hash_add_str(&hash, NULL, 10),
                        S2N_ERR_NULL);
                EXPECT_OK(s2n_fingerprint_hash_add_str(&hash, NULL, 0));
            };

            /* Null str with hash */
            {
                DEFER_CLEANUP(struct s2n_hash_state hash_state = { 0 }, s2n_hash_free);
                EXPECT_OK(s2n_test_hash_state_new(&hash_state));
                struct s2n_fingerprint_hash hash = { .hash = &hash_state };
                EXPECT_ERROR_WITH_ERRNO(s2n_fingerprint_hash_add_str(&hash, NULL, 10),
                        S2N_ERR_NULL);
                EXPECT_OK(s2n_fingerprint_hash_add_str(&hash, NULL, 0));
            };
        };

        /* Add to stuffer */
        {
            DEFER_CLEANUP(struct s2n_stuffer output = { 0 }, s2n_stuffer_free);
            EXPECT_SUCCESS(s2n_stuffer_alloc(&output, test_str_len * TEST_COUNT));
            struct s2n_fingerprint_hash hash = { .buffer = &output };

            for (size_t i = 1; i <= TEST_COUNT; i++) {
                EXPECT_OK(s2n_fingerprint_hash_add_str(&hash, test_str, test_str_len));
                EXPECT_EQUAL(s2n_stuffer_data_available(&output), test_str_len);

                uint8_t actual_value[sizeof(test_str)] = { 0 };
                EXPECT_SUCCESS(s2n_stuffer_read_bytes(&output, actual_value, test_str_len));
                EXPECT_BYTEARRAY_EQUAL(actual_value, test_str, test_str_len);
            }
        };

        /* Add to hash */
        {
            DEFER_CLEANUP(struct s2n_hash_state hash_state = { 0 }, s2n_hash_free);
            EXPECT_OK(s2n_test_hash_state_new(&hash_state));
            struct s2n_fingerprint_hash hash = { .hash = &hash_state };

            for (size_t i = 1; i <= TEST_COUNT; i++) {
                EXPECT_OK(s2n_fingerprint_hash_add_str(&hash, test_str, test_str_len));
                EXPECT_EQUAL(hash.hash->currently_in_hash, test_str_len * i);
            }
        };

        /* Error due to insufficient space */
        {
            struct s2n_stuffer output = { 0 };
            struct s2n_fingerprint_hash hash = { .buffer = &output };
            EXPECT_ERROR_WITH_ERRNO(
                    s2n_fingerprint_hash_add_str(&hash, test_str, test_str_len),
                    S2N_ERR_INSUFFICIENT_MEM_SIZE);

            EXPECT_SUCCESS(s2n_stuffer_alloc(&output, 1));
            EXPECT_ERROR_WITH_ERRNO(
                    s2n_fingerprint_hash_add_str(&hash, test_str, test_str_len),
                    S2N_ERR_INSUFFICIENT_MEM_SIZE);
            EXPECT_SUCCESS(s2n_stuffer_free(&output));

            EXPECT_SUCCESS(s2n_stuffer_alloc(&output, test_str_len - 1));
            EXPECT_ERROR_WITH_ERRNO(
                    s2n_fingerprint_hash_add_str(&hash, test_str, test_str_len),
                    S2N_ERR_INSUFFICIENT_MEM_SIZE);
            EXPECT_SUCCESS(s2n_stuffer_free(&output));

            EXPECT_SUCCESS(s2n_stuffer_alloc(&output, test_str_len));
            EXPECT_OK(s2n_fingerprint_hash_add_char(&hash, test_char));
            EXPECT_ERROR_WITH_ERRNO(
                    s2n_fingerprint_hash_add_str(&hash, test_str, test_str_len),
                    S2N_ERR_INSUFFICIENT_MEM_SIZE);
            EXPECT_SUCCESS(s2n_stuffer_free(&output));
        };
    };

    /* Test s2n_fingerprint_hash_digest */
    {
        /* Safety */
        {
            uint8_t output_value[1] = { 0 };
            EXPECT_ERROR_WITH_ERRNO(
                    s2n_fingerprint_hash_digest(NULL, output_value, sizeof(output_value)),
                    S2N_ERR_NULL);
        };

        /* Digest successfully calculated */
        {
            DEFER_CLEANUP(struct s2n_hash_state hash_state = { 0 }, s2n_hash_free);
            EXPECT_OK(s2n_test_hash_state_new(&hash_state));
            struct s2n_fingerprint_hash hash = { .hash = &hash_state };

            EXPECT_OK(s2n_fingerprint_hash_add_str(&hash, test_str, test_str_len));
            EXPECT_EQUAL(hash.hash->currently_in_hash, test_str_len);

            uint8_t actual_digest[sizeof(test_str_digest)] = { 0 };
            EXPECT_OK(s2n_fingerprint_hash_digest(&hash, actual_digest, sizeof(actual_digest)));
            EXPECT_BYTEARRAY_EQUAL(actual_digest, test_str_digest, sizeof(test_str_digest));
            EXPECT_EQUAL(hash.bytes_digested, test_str_len);
        };

        /* Hash can be reused after digest */
        {
            DEFER_CLEANUP(struct s2n_hash_state hash_state = { 0 }, s2n_hash_free);
            EXPECT_OK(s2n_test_hash_state_new(&hash_state));
            struct s2n_fingerprint_hash hash = { .hash = &hash_state };

            const size_t count = 10;
            for (size_t i = 0; i < count; i++) {
                uint8_t actual_digest[sizeof(test_str_digest)] = { 0 };
                EXPECT_OK(s2n_fingerprint_hash_add_str(&hash, test_str, test_str_len));
                EXPECT_OK(s2n_fingerprint_hash_digest(&hash, actual_digest, sizeof(actual_digest)));
                EXPECT_BYTEARRAY_EQUAL(actual_digest, test_str_digest, sizeof(test_str_digest));
            }
            EXPECT_EQUAL(hash.bytes_digested, test_str_len * count);
        };
    };

    /* Test s2n_fingerprint_hash_do_digest */
    {
        /* Safety */
        EXPECT_FALSE(s2n_fingerprint_hash_do_digest(NULL));

        struct s2n_fingerprint_hash hash = { 0 };
        EXPECT_FALSE(s2n_fingerprint_hash_do_digest(&hash));

        struct s2n_stuffer output = { 0 };
        hash.buffer = &output;
        EXPECT_FALSE(s2n_fingerprint_hash_do_digest(&hash));

        struct s2n_hash_state hash_state = { 0 };
        hash.hash = &hash_state;
        EXPECT_TRUE(s2n_fingerprint_hash_do_digest(&hash));
    };

    /* Test s2n_assert_grease_value */
    {
        EXPECT_TRUE(s2n_is_grease_value(0x0A0A));
        EXPECT_TRUE(s2n_is_grease_value(0xFAFA));
        EXPECT_FALSE(s2n_is_grease_value(0x0000));
        EXPECT_FALSE(s2n_is_grease_value(0x0001));
    };

    END_TEST();
}
