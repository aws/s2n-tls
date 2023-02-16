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

#include "utils/s2n_blob.h"

#include "api/s2n.h"
#include "s2n_test.h"
#include "utils/s2n_mem.h"

int main(int argc, char **argv)
{
    BEGIN_TEST();
    EXPECT_SUCCESS(s2n_disable_tls13_in_test());

    /* Null blob is not valid */
    EXPECT_ERROR(s2n_blob_validate(NULL));

#ifndef NDEBUG
    /* Invalid blob is not valid */
    struct s2n_blob b1 = { .data = 0, .size = 101 };
    EXPECT_ERROR(s2n_blob_validate(&b1));
#endif

    /* Size of 0 is OK if data is null */
    struct s2n_blob b2 = { 0 };
    EXPECT_SUCCESS(s2n_blob_init(&b2, 0, 0));
    EXPECT_OK(s2n_blob_validate(&b2));

    /* Valid blob is valid */
    uint8_t array[12];
    struct s2n_blob b3 = { 0 };
    EXPECT_SUCCESS(s2n_blob_init(&b3, array, sizeof(array)));
    EXPECT_OK(s2n_blob_validate(&b3));

    /* Null blob is not growable */
    EXPECT_FALSE(s2n_blob_is_growable(NULL));
    EXPECT_FAILURE(s2n_realloc(NULL, 24));
    EXPECT_FAILURE(s2n_free(NULL));

    /* Static blob is not growable or freeable */
    struct s2n_blob g1 = { 0 };
    EXPECT_SUCCESS(s2n_blob_init(&g1, array, 12));
    EXPECT_FALSE(s2n_blob_is_growable(&g1));
    EXPECT_FAILURE(s2n_realloc(&g1, 24));
    EXPECT_FAILURE(s2n_free(&g1));

    /* Empty blob is freeable */
    struct s2n_blob g2 = { 0 };
    EXPECT_TRUE(s2n_blob_is_growable(&g2));
    EXPECT_SUCCESS(s2n_free(&g2));

    /* Empty blob is growable */
    struct s2n_blob g3 = { 0 };
    EXPECT_TRUE(s2n_blob_is_growable(&g3));
    EXPECT_SUCCESS(s2n_realloc(&g3, 24));
    EXPECT_SUCCESS(s2n_free(&g3));

    /* Alloced blob can be freed */
    struct s2n_blob g4 = { 0 };
    EXPECT_SUCCESS(s2n_alloc(&g4, 12));
    EXPECT_TRUE(s2n_blob_is_growable(&g4));
    EXPECT_SUCCESS(s2n_free(&g4));

    /* Alloced blob can be realloced and data preserved */
    struct s2n_blob g5 = { 0 };
    uint8_t hello_world[] = "HELLO WORLD";
    EXPECT_SUCCESS(s2n_alloc(&g5, 12));
    EXPECT_TRUE(s2n_blob_is_growable(&g5));
    EXPECT_MEMCPY_SUCCESS(g5.data, hello_world, sizeof(hello_world));
    EXPECT_SUCCESS(s2n_realloc(&g5, 24));
    EXPECT_EQUAL(memcmp(g5.data, hello_world, sizeof(hello_world)), 0);
    EXPECT_SUCCESS(s2n_free(&g5));

    /* Alloced blob can be reallocated without leaking memory */
    struct s2n_blob g6 = { 0 };
    EXPECT_SUCCESS(s2n_alloc(&g6, 12));
    g6.size = 0;
    EXPECT_SUCCESS(s2n_realloc(&g6, g6.allocated + 12));
    EXPECT_SUCCESS(s2n_free(&g6));

    /* Down-casing works */
    struct s2n_blob g7 = { 0 };
    EXPECT_SUCCESS(s2n_blob_init(&g7, hello_world, sizeof(hello_world)));
    EXPECT_SUCCESS(s2n_blob_char_to_lower(&g7));
    EXPECT_SUCCESS(memcmp(g7.data, "hello world", sizeof(hello_world)));

    /* Slicing works */
    struct s2n_blob g8 = { 0 };
    uint8_t hello[] = "hello ";
    uint8_t world[] = "world";
    EXPECT_SUCCESS(s2n_blob_slice(&g7, &g8, strlen((char *) hello), sizeof(world)));
    EXPECT_EQUAL(memcmp(g8.data, world, sizeof(world)), 0);
    EXPECT_EQUAL(g8.size, sizeof(world));

    /* Test s2n_hex_string_to_bytes */
    {
        uint8_t test_mem[10] = { 0 };

        /* Test with output buffer too small */
        {
            const uint8_t long_input_str[] = "abcdef123456";
            struct s2n_blob output_blob = { 0 };

            /* Succeeds with output blob of the right size */
            EXPECT_SUCCESS(s2n_blob_init(&output_blob, test_mem, sizeof(long_input_str) / 2));
            EXPECT_SUCCESS(s2n_hex_string_to_bytes(long_input_str, &output_blob));

            /* Fails with output blob that's too small */
            EXPECT_SUCCESS(s2n_blob_init(&output_blob, test_mem, 1));
            EXPECT_FAILURE_WITH_ERRNO(s2n_hex_string_to_bytes(long_input_str, &output_blob),
                    S2N_ERR_INVALID_HEX);
        };

        /* Test with invalid characters */
        {
            struct s2n_blob output_blob = { 0 };
            EXPECT_SUCCESS(s2n_blob_init(&output_blob, test_mem, sizeof(test_mem)));

            EXPECT_SUCCESS(s2n_hex_string_to_bytes((const uint8_t *) "12", &output_blob));
            EXPECT_FAILURE_WITH_ERRNO(s2n_hex_string_to_bytes((const uint8_t *) "#2", &output_blob),
                    S2N_ERR_INVALID_HEX);
            EXPECT_FAILURE_WITH_ERRNO(s2n_hex_string_to_bytes((const uint8_t *) "1#", &output_blob),
                    S2N_ERR_INVALID_HEX);
        };

        struct {
            const char *input;
            size_t expected_output_size;
            uint8_t expected_output[sizeof(test_mem)];
        } test_cases[] = {
            { .input = "abcd", .expected_output = { 171, 205 }, .expected_output_size = 2 },
            { .input = "ab cd", .expected_output = { 171, 205 }, .expected_output_size = 2 },
            { .input = " abcd", .expected_output = { 171, 205 }, .expected_output_size = 2 },
            { .input = "abcd ", .expected_output = { 171, 205 }, .expected_output_size = 2 },
            { .input = "  ab     cd  ", .expected_output = { 171, 205 }, .expected_output_size = 2 },
            { .input = "", .expected_output = { 0 }, .expected_output_size = 0 },
            { .input = " ", .expected_output = { 0 }, .expected_output_size = 0 },
            { .input = "12 34 56 78 90", .expected_output = { 18, 52, 86, 120, 144 }, .expected_output_size = 5 },
            { .input = "1234567890", .expected_output = { 18, 52, 86, 120, 144 }, .expected_output_size = 5 },
        };
        for (size_t i = 0; i < s2n_array_len(test_cases); i++) {
            struct s2n_blob actual_output = { 0 };
            EXPECT_SUCCESS(s2n_blob_init(&actual_output, test_mem, sizeof(test_mem)));

            EXPECT_SUCCESS(s2n_hex_string_to_bytes((const uint8_t *) test_cases[i].input, &actual_output));
            EXPECT_BYTEARRAY_EQUAL(actual_output.data, test_cases[i].expected_output, test_cases[i].expected_output_size);
        }
    };

    END_TEST();
}
