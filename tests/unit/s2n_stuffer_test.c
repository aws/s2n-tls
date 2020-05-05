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

#include "s2n_test.h"

#include "stuffer/s2n_stuffer.h"
#include "utils/s2n_mem.h"

#include <s2n.h>

int main(int argc, char **argv)
{
    uint8_t entropy[2048] = {0};
    struct s2n_stuffer stuffer;
    uint8_t u8;
    uint16_t u16;
    uint32_t u32;
    uint64_t u64;

    BEGIN_TEST();

    /* Create a 100 byte stuffer */
    EXPECT_SUCCESS(s2n_stuffer_alloc(&stuffer, 100));

    /* Try to write 101 bytes */
    struct s2n_blob in = {.data = entropy,.size = 101 };
    EXPECT_FAILURE(s2n_stuffer_write(&stuffer, &in));

    /* Try to write 101 1-byte ints bytes */
    for (uint64_t i = 0; i < 100; i++) {
        uint64_t value = i * (0xff / 100);
        EXPECT_SUCCESS(s2n_stuffer_write_uint8(&stuffer, value));
    }
    EXPECT_FAILURE(s2n_stuffer_write_uint8(&stuffer, 1));

    struct s2n_blob copy_of_bytes = {0};
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

    /* Invalid blob should fail init */
    struct s2n_stuffer s1;
    struct s2n_blob b1 = {.data = 0,.size = 101 };
    EXPECT_FAILURE(s2n_stuffer_init(&s1, &b1));

    /* Valid empty blob should succeed init */
    struct s2n_stuffer s2;
    struct s2n_blob b2 = {.data = 0,.size = 0 };
    EXPECT_SUCCESS(s2n_stuffer_init(&s2, &b2));

    /* Valid blob should succeed init */
    struct s2n_stuffer s3;
    uint8_t a3[12];
    struct s2n_blob b3 = {.data = a3,.size = sizeof(a3)};
    EXPECT_SUCCESS(s2n_stuffer_init(&s3, &b3));

    /* Null blob should fail init */
    struct s2n_stuffer s4;
    EXPECT_FAILURE(s2n_stuffer_init(&s4, NULL));

    /* Null stuffer should fail init */
    struct s2n_blob b5 = {.data = 0,.size = 0 };
    EXPECT_FAILURE(s2n_stuffer_init(NULL, &b5));

    /* Check s2n_stuffer_is_valid() function */
    EXPECT_FALSE(s2n_stuffer_is_valid(NULL));
    uint8_t valid_blob_array[12];
    struct s2n_blob blob_valid = {.data = valid_blob_array,.size = sizeof(valid_blob_array)};
    struct s2n_blob blob_invalid = {.data = 0,.size = sizeof(valid_blob_array)};

    struct s2n_stuffer stuffer_valid;
    EXPECT_SUCCESS(s2n_stuffer_init(&stuffer_valid, &blob_valid));
    EXPECT_TRUE(s2n_stuffer_is_valid(&stuffer));

    struct s2n_stuffer stuffer_invalid1 = {.blob = blob_invalid};
    EXPECT_FALSE(s2n_stuffer_is_valid(&stuffer_invalid1));

    struct s2n_stuffer stuffer_invalid2 = {.blob = blob_valid, .write_cursor = 13};
    EXPECT_FALSE(s2n_stuffer_is_valid(&stuffer_invalid2));

    struct s2n_stuffer stuffer_invalid3 = {.blob = blob_valid, .read_cursor = 13};
    EXPECT_FALSE(s2n_stuffer_is_valid(&stuffer_invalid3));

    struct s2n_stuffer stuffer_invalid4 = {.blob = blob_valid, .read_cursor = 12, .write_cursor = 1};
    EXPECT_FALSE(s2n_stuffer_is_valid(&stuffer_invalid4));

    struct s2n_stuffer reserve_test_stuffer = {0};
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

    EXPECT_SUCCESS(s2n_stuffer_free(&stuffer));

    /* Test writing network-order vector lengths */
    {
        s2n_stuffer_cursor_t vector_cursor;
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&stuffer, 0));
        uint64_t actual_length = 0;
        const uint64_t expected_length = 10;

        /* Test unsupported lengths */
        uint8_t invalid_lengths[] = { -1, 0, 5, 7, 9 };
        for (int i = 0; i < s2n_array_len(invalid_lengths); i++) {
            /* Try to allocate space for an unsupported length */
            EXPECT_FAILURE_WITH_ERRNO(s2n_stuffer_start_vector(&stuffer, &vector_cursor, invalid_lengths[i]), S2N_ERR_UNIMPLEMENTED);

            /* Try to write an unsupported length */
            EXPECT_FAILURE_WITH_ERRNO(s2n_stuffer_end_vector(&stuffer, stuffer.write_cursor, invalid_lengths[i]), S2N_ERR_UNIMPLEMENTED);
        }

        /* Test supported lengths */
        typedef int (*generic_read_func_t)(struct s2n_stuffer *stuffer, void *value);
        struct {
            uint8_t length;
            uint64_t max_length_value;
            generic_read_func_t read_func;
        } valid_lengths[] = {
            { 1, UINT8_MAX,     (generic_read_func_t) s2n_stuffer_read_uint8 },
            { 2, UINT16_MAX,    (generic_read_func_t) s2n_stuffer_read_uint16 },
            { 3, 0xFFFFFF,      (generic_read_func_t) s2n_stuffer_read_uint24 },
            { 4, UINT32_MAX,    (generic_read_func_t) s2n_stuffer_read_uint32 },
            { 8, UINT64_MAX,    (generic_read_func_t) s2n_stuffer_read_uint64 }
        };
        for (int i = 0; i < s2n_array_len(valid_lengths); i++) {

            /* Test zero length value */
            {
                EXPECT_SUCCESS(s2n_stuffer_rewrite(&stuffer));

                EXPECT_SUCCESS(s2n_stuffer_start_vector(&stuffer, &vector_cursor, valid_lengths[i].length));

                EXPECT_SUCCESS(s2n_stuffer_end_vector(&stuffer, vector_cursor, valid_lengths[i].length));
                EXPECT_SUCCESS(valid_lengths[i].read_func(&stuffer, &actual_length));
                EXPECT_EQUAL(actual_length, 0);
            }

            /* Test small, known length value. Verify no data overriden. */
            {
                uint32_t actual_data, expected_data = 0x12ab34cd;
                EXPECT_SUCCESS(s2n_stuffer_rewrite(&stuffer));

                EXPECT_SUCCESS(s2n_stuffer_start_vector(&stuffer, &vector_cursor, valid_lengths[i].length));
                EXPECT_SUCCESS(s2n_stuffer_write_uint32(&stuffer, expected_data));

                EXPECT_SUCCESS(s2n_stuffer_end_vector(&stuffer, vector_cursor, valid_lengths[i].length));
                EXPECT_SUCCESS(valid_lengths[i].read_func(&stuffer, &actual_length));
                EXPECT_EQUAL(actual_length, sizeof(expected_data));

                EXPECT_SUCCESS(s2n_stuffer_read_uint32(&stuffer, &actual_data));
                EXPECT_EQUAL(actual_data, expected_data);
            }

            /* The stuffer can't handle enough data to test max values for lengths of 4 bytes or higher. */
            if (valid_lengths[i].length < 4) {
                /* Test max length value */
                {
                    EXPECT_SUCCESS(s2n_stuffer_rewrite(&stuffer));

                    EXPECT_SUCCESS(s2n_stuffer_start_vector(&stuffer, &vector_cursor, valid_lengths[i].length));
                    EXPECT_SUCCESS(s2n_stuffer_skip_write(&stuffer, valid_lengths[i].max_length_value));

                    EXPECT_SUCCESS(s2n_stuffer_end_vector(&stuffer, vector_cursor, valid_lengths[i].length));
                    EXPECT_SUCCESS(valid_lengths[i].read_func(&stuffer, &actual_length));
                    EXPECT_EQUAL(actual_length, valid_lengths[i].max_length_value);
                }

                /* Test length value too long for requested space */
                {
                    EXPECT_SUCCESS(s2n_stuffer_rewrite(&stuffer));

                    EXPECT_SUCCESS(s2n_stuffer_start_vector(&stuffer, &vector_cursor, valid_lengths[i].length));
                    EXPECT_SUCCESS(s2n_stuffer_skip_write(&stuffer, valid_lengths[i].max_length_value + 1));

                    EXPECT_FAILURE_WITH_ERRNO(s2n_stuffer_end_vector(&stuffer, vector_cursor, valid_lengths[i].length),
                            S2N_ERR_SIZE_MISMATCH);
                }
            }

            /* Test chained writes */
            {
                /* Write multiple vectors with extra data before and after */
                uint8_t before_length = 5, first_vector_length = 10, between_length = 3,
                        second_vector_length = 7, after_length = 3;

                EXPECT_SUCCESS(s2n_stuffer_rewrite(&stuffer));
                EXPECT_SUCCESS(s2n_stuffer_skip_write(&stuffer, before_length));
                EXPECT_SUCCESS(s2n_stuffer_start_vector(&stuffer, &vector_cursor, valid_lengths[i].length));
                EXPECT_SUCCESS(s2n_stuffer_skip_write(&stuffer, first_vector_length));
                EXPECT_SUCCESS(s2n_stuffer_end_vector(&stuffer, vector_cursor, valid_lengths[i].length));
                EXPECT_SUCCESS(s2n_stuffer_skip_write(&stuffer, between_length));
                EXPECT_SUCCESS(s2n_stuffer_start_vector(&stuffer, &vector_cursor, valid_lengths[i].length));
                EXPECT_SUCCESS(s2n_stuffer_skip_write(&stuffer, second_vector_length));
                EXPECT_SUCCESS(s2n_stuffer_end_vector(&stuffer, vector_cursor, valid_lengths[i].length));
                EXPECT_SUCCESS(s2n_stuffer_skip_write(&stuffer, after_length));
                EXPECT_EQUAL(s2n_stuffer_data_available(&stuffer), before_length + first_vector_length
                        + between_length + second_vector_length + after_length + (valid_lengths[i].length * 2));

                /* Read everything back, verifying correct length values */
                EXPECT_SUCCESS(s2n_stuffer_skip_read(&stuffer, before_length));
                EXPECT_SUCCESS(valid_lengths[i].read_func(&stuffer, &actual_length));
                EXPECT_EQUAL(actual_length, first_vector_length);
                EXPECT_SUCCESS(s2n_stuffer_skip_read(&stuffer, first_vector_length));
                EXPECT_SUCCESS(s2n_stuffer_skip_read(&stuffer, between_length));
                EXPECT_SUCCESS(valid_lengths[i].read_func(&stuffer, &actual_length));
                EXPECT_EQUAL(actual_length, second_vector_length);
                EXPECT_SUCCESS(s2n_stuffer_skip_read(&stuffer, second_vector_length));
                EXPECT_SUCCESS(s2n_stuffer_skip_read(&stuffer, after_length));
                EXPECT_EQUAL(s2n_stuffer_data_available(&stuffer), 0);
            }
        }

        /* Test writing after resize / realloc */
        {
            /* Reset allocated memory for stuffer */
            EXPECT_SUCCESS(s2n_stuffer_free(&stuffer));
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&stuffer, 0));

            EXPECT_SUCCESS(s2n_stuffer_start_vector(&stuffer, &vector_cursor, sizeof(actual_length)));

            uint8_t *data_before_resize = stuffer.blob.data;
            EXPECT_SUCCESS(s2n_stuffer_resize(&stuffer, UINT16_MAX));
            EXPECT_NOT_EQUAL(data_before_resize, stuffer.blob.data);

            EXPECT_SUCCESS(s2n_stuffer_skip_write(&stuffer, expected_length));
            EXPECT_SUCCESS(s2n_stuffer_end_vector(&stuffer, vector_cursor, sizeof(actual_length)));

            EXPECT_SUCCESS(s2n_stuffer_read_uint64(&stuffer, &actual_length));
            EXPECT_EQUAL(actual_length, expected_length);
        }

        /* Test writing after read cursor passes vector start */
        {
            EXPECT_SUCCESS(s2n_stuffer_rewrite(&stuffer));

            EXPECT_SUCCESS(s2n_stuffer_start_vector(&stuffer, &vector_cursor, sizeof(actual_length)));

            EXPECT_SUCCESS(s2n_stuffer_skip_write(&stuffer, expected_length));
            EXPECT_SUCCESS(s2n_stuffer_skip_read(&stuffer, expected_length));

            EXPECT_FAILURE_WITH_ERRNO(s2n_stuffer_end_vector(&stuffer, vector_cursor, sizeof(actual_length)),
                    S2N_ERR_SAFETY);
        }

        /* Test that length value is always zero before the length is written */
        {
            EXPECT_SUCCESS(s2n_stuffer_rewrite(&stuffer));

            uint8_t fill_value = 0xFF;
            memset(stuffer.blob.data, fill_value, stuffer.blob.size);
            EXPECT_SUCCESS(s2n_stuffer_skip_write(&stuffer, sizeof(fill_value)));
            EXPECT_SUCCESS(s2n_stuffer_start_vector(&stuffer, &vector_cursor, sizeof(fill_value)));

            EXPECT_SUCCESS(s2n_stuffer_read_uint8(&stuffer, (uint8_t*) &actual_length));
            EXPECT_EQUAL(actual_length, fill_value);

            EXPECT_SUCCESS(s2n_stuffer_read_uint8(&stuffer, (uint8_t*) &actual_length));
            EXPECT_EQUAL(actual_length, 0);
        }

        EXPECT_SUCCESS(s2n_stuffer_free(&stuffer));
    }

    END_TEST();
}
