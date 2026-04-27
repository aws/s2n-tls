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

/* Include the .c file directly to access the static helper */
#include "crypto/s2n_dhe.c"

int main(int argc, char **argv)
{
    BEGIN_TEST();

    /* No padding needed when computed_size == expected_size */
    {
        uint8_t data[] = { 0xAA, 0xBB, 0xCC, 0xDD };
        struct s2n_blob key = { 0 };
        EXPECT_SUCCESS(s2n_blob_init(&key, data, sizeof(data)));

        s2n_dh_pad_shared_secret(&key, 4, 4);
        EXPECT_EQUAL(key.size, 4);
        EXPECT_EQUAL(data[0], 0xAA);
        EXPECT_EQUAL(data[1], 0xBB);
        EXPECT_EQUAL(data[2], 0xCC);
        EXPECT_EQUAL(data[3], 0xDD);
    };

    /* Padding needed when computed_size < expected_size */
    {
        uint8_t data[8] = { 0xAA, 0xBB, 0xCC, 0x00, 0x00, 0x00, 0x00, 0x00 };
        struct s2n_blob key = { 0 };
        EXPECT_SUCCESS(s2n_blob_init(&key, data, 3));

        s2n_dh_pad_shared_secret(&key, 3, 8);
        EXPECT_EQUAL(key.size, 8);
        /* First 5 bytes should be zero padding */
        for (int i = 0; i < 5; i++) {
            EXPECT_EQUAL(data[i], 0x00);
        }
        /* Last 3 bytes should be the original data */
        EXPECT_EQUAL(data[5], 0xAA);
        EXPECT_EQUAL(data[6], 0xBB);
        EXPECT_EQUAL(data[7], 0xCC);
    };

    END_TEST();
}
