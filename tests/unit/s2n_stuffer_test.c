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

#include "stuffer/s2n_stuffer.h"

#include "api/s2n.h"
#include "s2n_test.h"
#include "utils/s2n_mem.h"

int main(int argc, char **argv)
{
    uint8_t entropy[2048] = { 0 };
    struct s2n_stuffer stuffer = { 0 };
    uint8_t u8;
    uint16_t u16;
    uint32_t u32;
    uint64_t u64;

    BEGIN_TEST();
    EXPECT_SUCCESS(s2n_disable_tls13_in_test());

    /* Create a 100 byte stuffer */
    EXPECT_SUCCESS(s2n_stuffer_alloc(&stuffer, 100));

    /* Try to write 101 bytes */
    struct s2n_blob in = { 0 };
    EXPECT_SUCCESS(s2n_blob_init(&in, entropy, 101));
    EXPECT_FAILURE(s2n_stuffer_write(&stuffer, &in));

    /* Try to write 101 1-byte ints bytes */
    for (uint64_t i = 0; i < 100; i++) {
        uint64_t value = i * (0xff / 100);
        EXPECT_SUCCESS(s2n_stuffer_write_uint8(&stuffer, value));
    }
    EXPECT_FAILURE(s2n_stuffer_write_uint8(&stuffer, 1));

    struct s2n_blob copy_of_bytes = { 0 };
    EXPECT_SUCCESS(s2n_stuffer_extract_blob(&stuffer, &copy_of_bytes));

    /* Read those back, and expect the same results */
    for (uint64_t i = 0; i < 100; i++) {
        uint64_t value = i * (0xff / 100);
        EXPECT_SUCCESS(s2n_stuffer_read_uint8(&stuffer, &u8));
        EXPECT_EQUAL(value, u8);
        EXPECT_EQUAL(copy_of_bytes.data[i], u8);
    }

    /* The copy_of_bytes should have the same values */
    for (uint64_t i = 0; i < 100; i++) {
        uint64_t value = i * (0xff / 100);
        EXPECT_EQUAL(copy_of_bytes.data[i], value);
    }

    EXPECT_FAILURE(s2n_stuffer_read_uint8(&stuffer, &u8));

    /* Try to write 51 2-byte ints bytes */
    EXPECT_SUCCESS(s2n_stuffer_wipe(&stuffer));
    for (uint64_t i = 0; i < 50; i++) {
        uint64_t value = i * (0xffff / 50);
        EXPECT_SUCCESS(s2n_stuffer_write_uint16(&stuffer, value));
    }
    EXPECT_FAILURE(s2n_stuffer_write_uint16(&stuffer, 1));

    /* Read those back, and expect the same results */
    for (uint64_t i = 0; i < 50; i++) {
        uint64_t value = i * (0xffff / 50);
        EXPECT_SUCCESS(s2n_stuffer_read_uint16(&stuffer, &u16));
        EXPECT_EQUAL(value, u16);
    }
    EXPECT_FAILURE(s2n_stuffer_read_uint16(&stuffer, &u16));

    /* Try to write 34 3-byte ints bytes */
    EXPECT_SUCCESS(s2n_stuffer_wipe(&stuffer));
    for (uint64_t i = 0; i < 33; i++) {
        uint64_t value = i * (0xffffff / 33);
        EXPECT_SUCCESS(s2n_stuffer_write_uint24(&stuffer, value));
    }
    EXPECT_FAILURE(s2n_stuffer_write_uint24(&stuffer, 1));

    /* Read those back, and expect the same results */
    for (uint64_t i = 0; i < 33; i++) {
        uint64_t value = i * (0xffffff / 33);
        EXPECT_SUCCESS(s2n_stuffer_read_uint24(&stuffer, &u32));
        EXPECT_EQUAL(value, u32);
    }
    EXPECT_FAILURE(s2n_stuffer_read_uint16(&stuffer, &u16));

    /* Try to write 26 4-byte ints bytes */
    EXPECT_SUCCESS(s2n_stuffer_wipe(&stuffer));
    for (uint64_t i = 0; i < 25; i++) {
        uint64_t value = i * (0xffffffff / 25);
        EXPECT_SUCCESS(s2n_stuffer_write_uint32(&stuffer, value));
    }
    EXPECT_FAILURE(s2n_stuffer_write_uint32(&stuffer, 1));

    /* Read those back, and expect the same results */
    for (uint64_t i = 0; i < 25; i++) {
        uint64_t value = i * (0xffffffff / 25);
        EXPECT_SUCCESS(s2n_stuffer_read_uint32(&stuffer, &u32));
        EXPECT_EQUAL(value, u32);
    }
    EXPECT_FAILURE(s2n_stuffer_read_uint32(&stuffer, &u32));

    /* Try to write 13 8-byte ints bytes */
    EXPECT_SUCCESS(s2n_stuffer_wipe(&stuffer));
    for (int i = 0; i < 12; i++) {
        uint64_t value = i * (0xffffffffffffffff / 12);
        EXPECT_SUCCESS(s2n_stuffer_write_uint64(&stuffer, value));
    }
    EXPECT_FAILURE(s2n_stuffer_write_uint64(&stuffer, 1));

    /* Read those back, and expect the same results */
    for (int i = 0; i < 12; i++) {
        uint64_t value = i * (0xffffffffffffffff / 12);
        EXPECT_SUCCESS(s2n_stuffer_read_uint64(&stuffer, &u64));
        EXPECT_EQUAL(value, u64);
    }
    EXPECT_FAILURE(s2n_stuffer_read_uint64(&stuffer, &u64));

    EXPECT_SUCCESS(s2n_stuffer_free(&stuffer));

    /* Can still read the copy_of_bytes even once the stuffer has been overwritten and freed */
    for (uint64_t i = 0; i < 100; i++) {
        uint64_t value = i * (0xff / 100);
        EXPECT_EQUAL(copy_of_bytes.data[i], value);
    }
    EXPECT_SUCCESS(s2n_free(&copy_of_bytes));

#ifndef NDEBUG
    /* Invalid blob should fail init */
    struct s2n_stuffer s1 = { 0 };
    struct s2n_blob b1 = { .data = 0, .size = 101 };
    EXPECT_FAILURE(s2n_stuffer_init(&s1, &b1));
#endif

    /* Valid empty blob should succeed init */
    struct s2n_stuffer s2 = { 0 };
    struct s2n_blob b2 = { 0 };
    EXPECT_SUCCESS(s2n_blob_init(&b2, 0, 0));
    EXPECT_SUCCESS(s2n_stuffer_init(&s2, &b2));

    /* Valid blob should succeed init */
    struct s2n_stuffer s3 = { 0 };
    uint8_t a3[12];
    struct s2n_blob b3 = { 0 };
    EXPECT_SUCCESS(s2n_blob_init(&b3, a3, sizeof(a3)));
    EXPECT_SUCCESS(s2n_stuffer_init(&s3, &b3));

    /* Null blob should fail init */
    struct s2n_stuffer s4 = { 0 };
    EXPECT_FAILURE(s2n_stuffer_init(&s4, NULL));

    /* Null stuffer should fail init */
    struct s2n_blob b5 = { 0 };
    EXPECT_SUCCESS(s2n_blob_init(&b5, 0, 0));
    EXPECT_FAILURE(s2n_stuffer_init(NULL, &b5));

    /* Check s2n_stuffer_validate() function */
    EXPECT_ERROR(s2n_stuffer_validate(NULL));
    uint8_t valid_blob_array[12];
    struct s2n_blob blob_valid = { 0 };
    EXPECT_SUCCESS(s2n_blob_init(&blob_valid, valid_blob_array, sizeof(valid_blob_array)));

    struct s2n_stuffer stuffer_valid = { 0 };
    EXPECT_SUCCESS(s2n_stuffer_init(&stuffer_valid, &blob_valid));
    EXPECT_OK(s2n_stuffer_validate(&stuffer));

#ifndef NDEBUG
    struct s2n_blob blob_invalid = { .data = 0, .size = sizeof(valid_blob_array) };
    struct s2n_stuffer stuffer_invalid1 = { .blob = blob_invalid };
    EXPECT_ERROR(s2n_stuffer_validate(&stuffer_invalid1));

    struct s2n_stuffer stuffer_invalid2 = { .blob = blob_valid, .write_cursor = 13 };
    EXPECT_ERROR(s2n_stuffer_validate(&stuffer_invalid2));

    struct s2n_stuffer stuffer_invalid3 = { .blob = blob_valid, .read_cursor = 13 };
    EXPECT_ERROR(s2n_stuffer_validate(&stuffer_invalid3));

    struct s2n_stuffer stuffer_invalid4 = { .blob = blob_valid, .read_cursor = 12, .write_cursor = 1 };
    EXPECT_ERROR(s2n_stuffer_validate(&stuffer_invalid4));
#endif

    struct s2n_stuffer reserve_test_stuffer = { 0 };
    EXPECT_SUCCESS(s2n_stuffer_alloc(&reserve_test_stuffer, 1024));
    EXPECT_EQUAL(s2n_stuffer_space_remaining(&reserve_test_stuffer), 1024);
    EXPECT_EQUAL(s2n_stuffer_data_available(&reserve_test_stuffer), 0);
    EXPECT_FAILURE(s2n_stuffer_reserve_space(&reserve_test_stuffer, 2048));
    EXPECT_EQUAL(s2n_stuffer_space_remaining(&reserve_test_stuffer), 1024);
    EXPECT_EQUAL(s2n_stuffer_data_available(&reserve_test_stuffer), 0);
    EXPECT_SUCCESS(s2n_stuffer_free(&reserve_test_stuffer));

    EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&reserve_test_stuffer, 1024));
    EXPECT_EQUAL(s2n_stuffer_space_remaining(&reserve_test_stuffer), 1024);
    EXPECT_EQUAL(s2n_stuffer_data_available(&reserve_test_stuffer), 0);
    EXPECT_SUCCESS(s2n_stuffer_reserve_space(&reserve_test_stuffer, 2048));
    EXPECT_EQUAL(s2n_stuffer_space_remaining(&reserve_test_stuffer), 2048);
    EXPECT_EQUAL(s2n_stuffer_data_available(&reserve_test_stuffer), 0);
    EXPECT_SUCCESS(s2n_stuffer_free(&reserve_test_stuffer));

    /* Test: s2n_stuffer_init_written */
    {
        uint8_t data[] = "hello world";
        uint8_t input[sizeof(data)] = { 0 };
        uint8_t output[sizeof(data)] = { 0 };

        struct s2n_blob blob = { 0 };
        EXPECT_SUCCESS(s2n_blob_init(&blob, input, sizeof(input)));

        /* Repeat control to show behavior is consistent */
        for (size_t i = 0; i < 3; i++) {
            struct s2n_stuffer unwritten_stuffer = { 0 };
            EXPECT_SUCCESS(s2n_stuffer_init(&unwritten_stuffer, &blob));
            EXPECT_EQUAL(s2n_stuffer_data_available(&unwritten_stuffer), 0);
            EXPECT_FAILURE_WITH_ERRNO(s2n_stuffer_read_bytes(&unwritten_stuffer, output, sizeof(output)),
                    S2N_ERR_STUFFER_OUT_OF_DATA);
            EXPECT_SUCCESS(s2n_stuffer_write_bytes(&unwritten_stuffer, data, sizeof(data)));
        }

        /* Repeat test to show behavior is consistent */
        for (size_t i = 0; i < 3; i++) {
            struct s2n_stuffer written_stuffer = { 0 };
            EXPECT_SUCCESS(s2n_stuffer_init_written(&written_stuffer, &blob));
            EXPECT_EQUAL(s2n_stuffer_data_available(&written_stuffer), sizeof(data));
            EXPECT_SUCCESS(s2n_stuffer_read_bytes(&written_stuffer, output, sizeof(output)));
            EXPECT_BYTEARRAY_EQUAL(data, output, sizeof(output));
            EXPECT_FAILURE_WITH_ERRNO(s2n_stuffer_write_bytes(&written_stuffer, data, sizeof(data)),
                    S2N_ERR_STUFFER_IS_FULL);
        }
    };

    END_TEST();
}
