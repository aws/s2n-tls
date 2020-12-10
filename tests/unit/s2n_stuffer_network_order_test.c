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

#include <s2n.h>

#include "s2n_test.h"
#include "stuffer/s2n_stuffer.h"
#include "utils/s2n_mem.h"

#define SIZEOF_UINT24 3

int s2n_stuffer_write_network_order(struct s2n_stuffer *stuffer, uint32_t input, uint8_t length);
int s2n_stuffer_write_reservation(struct s2n_stuffer_reservation* reservation, const uint32_t u);

int main(int argc, char **argv)
{
    BEGIN_TEST();
    EXPECT_SUCCESS(s2n_disable_tls13());

    struct s2n_stuffer stuffer;

    /* s2n_stuffer_write_network_order */
    {
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&stuffer, 0));

        /* Null checks */
        EXPECT_FAILURE(s2n_stuffer_write_network_order(NULL, 0, 1));

        /* No-op for zero length */
        EXPECT_SUCCESS(s2n_stuffer_write_network_order(&stuffer, 0x00, 0));
        EXPECT_EQUAL(s2n_stuffer_data_available(&stuffer), 0);

        uint8_t byte_length;

        /* uint8_t */
        {
            byte_length = sizeof(uint8_t);
            uint8_t actual_value;

            for (int i = 0; i <= UINT8_MAX; i++) {
                EXPECT_SUCCESS(s2n_stuffer_write_network_order(&stuffer, i, byte_length));
                EXPECT_SUCCESS(s2n_stuffer_read_uint8(&stuffer, &actual_value));
                EXPECT_EQUAL(i, actual_value);
            }
        }

        /* uint16_t */
        {
            byte_length = sizeof(uint16_t);
            uint16_t actual_value;

            for (int i = 0; i < UINT16_MAX; i++) {
                EXPECT_SUCCESS(s2n_stuffer_write_network_order(&stuffer, i, byte_length));
                EXPECT_SUCCESS(s2n_stuffer_read_uint16(&stuffer, &actual_value));
                EXPECT_EQUAL(i, actual_value);
            }
        }

        /* uint24 */
        {
            byte_length = 3;
            uint32_t actual_value;
            uint32_t test_values[] = { 0x000001, 0x0000FF, 0xABCDEF, 0xFFFFFF };

            for (int i = 0; i < s2n_array_len(test_values); i++) {
                EXPECT_SUCCESS(s2n_stuffer_write_network_order(&stuffer, test_values[i], byte_length));
                EXPECT_SUCCESS(s2n_stuffer_read_uint24(&stuffer, &actual_value));
                EXPECT_EQUAL(test_values[i], actual_value);
            }

            uint16_t prime = 257;
            for (uint32_t i = 0; i < 0xFFFFFF - prime; i += prime) {
                EXPECT_SUCCESS(s2n_stuffer_write_network_order(&stuffer, i, byte_length));
                EXPECT_SUCCESS(s2n_stuffer_read_uint24(&stuffer, &actual_value));
                EXPECT_EQUAL(i, actual_value);
            }
        }

        /* uint32_t */
        {
            byte_length = sizeof(uint32_t);
            uint32_t actual_value;
            uint32_t test_values[] = { 0x00000001, 0x000000FF, 0xABCDEF12, UINT32_MAX };

            for (int i = 0; i < s2n_array_len(test_values); i++) {
                EXPECT_SUCCESS(s2n_stuffer_write_network_order(&stuffer, test_values[i], byte_length));
                EXPECT_SUCCESS(s2n_stuffer_read_uint32(&stuffer, &actual_value));
                EXPECT_EQUAL(test_values[i], actual_value);
            }

            uint32_t prime = 65537;
            for (uint32_t i = 0; i < UINT32_MAX - prime; i += prime) {
                EXPECT_SUCCESS(s2n_stuffer_write_network_order(&stuffer, i, byte_length));
                EXPECT_SUCCESS(s2n_stuffer_read_uint32(&stuffer, &actual_value));
                EXPECT_EQUAL(i, actual_value);
            }
        }

        EXPECT_SUCCESS(s2n_stuffer_free(&stuffer));
    }

    /* s2n_stuffer_reserve_uint16 */
    {
        uint16_t actual_value;
        struct s2n_stuffer_reservation reservation = { 0 };
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&stuffer, 0));

        /* Null checks */
        EXPECT_FAILURE(s2n_stuffer_reserve_uint16(NULL, &reservation));
        EXPECT_FAILURE(s2n_stuffer_reserve_uint16(&stuffer, NULL));

        /* Happy case: successfully reserves space for a uint16_t */
        {
            /* Write some data. We want to verify it isn't overwritten. */
            uint16_t data_before = 5;
            EXPECT_SUCCESS(s2n_stuffer_write_uint16(&stuffer, data_before));

            /* Reserve uint16 */
            EXPECT_SUCCESS(s2n_stuffer_reserve_uint16(&stuffer, &reservation));
            EXPECT_EQUAL(reservation.stuffer, &stuffer);
            EXPECT_EQUAL(reservation.write_cursor, sizeof(uint16_t));
            EXPECT_EQUAL(reservation.length, sizeof(uint16_t));

            /* Reserve uint16 again */
            EXPECT_SUCCESS(s2n_stuffer_reserve_uint16(&stuffer, &reservation));
            EXPECT_EQUAL(reservation.stuffer, &stuffer);
            EXPECT_EQUAL(reservation.write_cursor, sizeof(uint16_t) * 2);
            EXPECT_EQUAL(reservation.length, sizeof(uint16_t));

            /* Write some more data. We want to verify it isn't overwritten. */
            uint16_t data_after = -1;
            EXPECT_SUCCESS(s2n_stuffer_write_uint16(&stuffer, data_after));

            /* Make sure expected values read back */
            uint8_t actual_bytes[sizeof(uint16_t)], expected_bytes[] = { S2N_WIPE_PATTERN, S2N_WIPE_PATTERN };
            EXPECT_SUCCESS(s2n_stuffer_read_uint16(&stuffer, &actual_value));
            EXPECT_EQUAL(actual_value, data_before);
            EXPECT_SUCCESS(s2n_stuffer_read_bytes(&stuffer, actual_bytes, sizeof(uint16_t)));
            EXPECT_BYTEARRAY_EQUAL(actual_bytes, expected_bytes, sizeof(uint16_t));
            EXPECT_SUCCESS(s2n_stuffer_read_bytes(&stuffer, actual_bytes, sizeof(uint16_t)));
            EXPECT_BYTEARRAY_EQUAL(actual_bytes, expected_bytes, sizeof(uint16_t));
            EXPECT_SUCCESS(s2n_stuffer_read_uint16(&stuffer, &actual_value));
            EXPECT_EQUAL(actual_value, data_after);
        }

        EXPECT_SUCCESS(s2n_stuffer_free(&stuffer));
    }

    /* s2n_stuffer_reserve_uint24 */
    {
        uint16_t actual_value;
        struct s2n_stuffer_reservation reservation = { 0 };
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&stuffer, 0));

        /* Null checks */
        EXPECT_FAILURE(s2n_stuffer_reserve_uint24(NULL, &reservation));
        EXPECT_FAILURE(s2n_stuffer_reserve_uint24(&stuffer, NULL));

        /* Happy case: successfully reserves space for a uint24_t */
        {
            /* Write some data. We want to verify it isn't overwritten. */
            uint16_t data_before = 5;
            EXPECT_SUCCESS(s2n_stuffer_write_uint16(&stuffer, data_before));

            /* Reserve uint24 */
            EXPECT_SUCCESS(s2n_stuffer_reserve_uint24(&stuffer, &reservation));
            EXPECT_EQUAL(reservation.stuffer, &stuffer);
            EXPECT_EQUAL(reservation.write_cursor, sizeof(uint16_t));
            EXPECT_EQUAL(reservation.length, SIZEOF_UINT24);

            /* Reserve uint24 again */
            EXPECT_SUCCESS(s2n_stuffer_reserve_uint24(&stuffer, &reservation));
            EXPECT_EQUAL(reservation.stuffer, &stuffer);
            EXPECT_EQUAL(reservation.write_cursor, sizeof(uint16_t) + SIZEOF_UINT24);
            EXPECT_EQUAL(reservation.length, SIZEOF_UINT24);

            /* Write some more data. We want to verify it isn't overwritten. */
            uint16_t data_after = -1;
            EXPECT_SUCCESS(s2n_stuffer_write_uint16(&stuffer, data_after));

            /* Make sure expected values read back */
            uint8_t actual_bytes[SIZEOF_UINT24], expected_bytes[] = { S2N_WIPE_PATTERN, S2N_WIPE_PATTERN, S2N_WIPE_PATTERN };
            EXPECT_SUCCESS(s2n_stuffer_read_uint16(&stuffer, &actual_value));
            EXPECT_EQUAL(actual_value, data_before);
            EXPECT_SUCCESS(s2n_stuffer_read_bytes(&stuffer, actual_bytes, SIZEOF_UINT24));
            EXPECT_BYTEARRAY_EQUAL(actual_bytes, expected_bytes, SIZEOF_UINT24);
            EXPECT_SUCCESS(s2n_stuffer_read_bytes(&stuffer, actual_bytes, SIZEOF_UINT24));
            EXPECT_BYTEARRAY_EQUAL(actual_bytes, expected_bytes, SIZEOF_UINT24);
            EXPECT_SUCCESS(s2n_stuffer_read_uint16(&stuffer, &actual_value));
            EXPECT_EQUAL(actual_value, data_after);
        }

        EXPECT_SUCCESS(s2n_stuffer_free(&stuffer));
    }

    /* s2n_stuffer_write_reservation */
    {
        uint16_t actual_value;
        struct s2n_stuffer_reservation reservation = { 0 };
        struct s2n_stuffer_reservation other_reservation = { 0 };
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&stuffer, 0));
        uint32_t expected_write_cursor = stuffer.write_cursor;

        /* Null checks */
        reservation.stuffer = NULL;
        EXPECT_FAILURE(s2n_stuffer_write_reservation(&reservation, 0));
        EXPECT_EQUAL(stuffer.write_cursor, expected_write_cursor);
        reservation.stuffer = &stuffer;

        /* Should throw an error if reservation has wrong size */
        reservation.length = sizeof(uint64_t);
        EXPECT_FAILURE_WITH_ERRNO(s2n_stuffer_write_reservation(&reservation, 0), S2N_ERR_SAFETY);
        EXPECT_EQUAL(stuffer.write_cursor, expected_write_cursor);
        reservation.length = sizeof(uint16_t);

        /* Should throw an error if value length does not match reservation length */
        EXPECT_FAILURE_WITH_ERRNO(s2n_stuffer_write_reservation(&reservation, UINT32_MAX), S2N_ERR_SAFETY);
        EXPECT_EQUAL(stuffer.write_cursor, expected_write_cursor);

        /* Should throw an error if rewriting would require an invalid stuffer state.
         * ( A write cursor being greater than the high water mark is an invalid stuffer state.) */
        reservation.write_cursor = stuffer.high_water_mark + 1;
        EXPECT_FAILURE_WITH_ERRNO(s2n_stuffer_write_reservation(&reservation, 0), S2N_ERR_SAFETY);
        EXPECT_EQUAL(stuffer.write_cursor, expected_write_cursor);

        /* Happy case: successfully rewrites a uint16_t */
        {
            /* Write some data. We want to verify it isn't overwritten. */
            uint16_t data_before = 5;
            EXPECT_SUCCESS(s2n_stuffer_write_uint16(&stuffer, data_before));

            /* Reserve uint16s */
            EXPECT_SUCCESS(s2n_stuffer_reserve_uint16(&stuffer, &reservation));
            EXPECT_SUCCESS(s2n_stuffer_reserve_uint16(&stuffer, &other_reservation));

            /* Write some more data. We want to verify it isn't overwritten. */
            uint16_t data_after = -1;
            EXPECT_SUCCESS(s2n_stuffer_write_uint16(&stuffer, data_after));

            /* Rewrite reserved uint16s */
            uint16_t expected_value = 0xabcd;
            expected_write_cursor = stuffer.write_cursor;
            EXPECT_SUCCESS(s2n_stuffer_write_reservation(&reservation, expected_value));
            EXPECT_EQUAL(stuffer.write_cursor, expected_write_cursor);
            EXPECT_SUCCESS(s2n_stuffer_write_reservation(&other_reservation, expected_value));
            EXPECT_EQUAL(stuffer.write_cursor, expected_write_cursor);

            /* Make sure expected values read back */
            EXPECT_SUCCESS(s2n_stuffer_read_uint16(&stuffer, &actual_value));
            EXPECT_EQUAL(actual_value, data_before);
            EXPECT_SUCCESS(s2n_stuffer_read_uint16(&stuffer, &actual_value));
            EXPECT_EQUAL(actual_value, expected_value);
            EXPECT_SUCCESS(s2n_stuffer_read_uint16(&stuffer, &actual_value));
            EXPECT_EQUAL(actual_value, expected_value);
            EXPECT_SUCCESS(s2n_stuffer_read_uint16(&stuffer, &actual_value));
            EXPECT_EQUAL(actual_value, data_after);
        }

        EXPECT_SUCCESS(s2n_stuffer_free(&stuffer));
    }

    /* s2n_stuffer_write_vector_size */
    {
        uint16_t actual_value;
        struct s2n_stuffer_reservation reservation = { 0 };
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&stuffer, 0));

        /* Happy cases */
        uint16_t test_sizes[] = { 0, 1, 5, 0x88, 0xF0, 0xFF };
        for( int i = 0; i < s2n_array_len(test_sizes); i++) {
            EXPECT_SUCCESS(s2n_stuffer_reserve_uint16(&stuffer, &reservation));

            EXPECT_SUCCESS(s2n_stuffer_skip_write(&stuffer, test_sizes[i]));
            EXPECT_SUCCESS(s2n_stuffer_write_vector_size(&reservation));

            EXPECT_SUCCESS(s2n_stuffer_read_uint16(&stuffer, &actual_value));
            EXPECT_EQUAL(actual_value, test_sizes[i]);

            EXPECT_SUCCESS(s2n_stuffer_skip_read(&stuffer, test_sizes[i]));
        }

        EXPECT_SUCCESS(s2n_stuffer_free(&stuffer));
    }

    END_TEST();
}
