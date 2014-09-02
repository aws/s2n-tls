/*
 * Copyright 2014 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

#include "testlib/s2n_testlib.h"
#include "stuffer/s2n_stuffer.h"
#include "utils/s2n_random.h"

int main(int argc, char **argv)
{
    uint8_t pad[100];
    struct s2n_blob b = {.data = pad,.size = sizeof(pad) };
    struct s2n_stuffer stuffer;
    uint8_t u8;
    uint16_t u16;
    uint32_t u32;
    uint64_t u64;

    BEGIN_TEST();

    /* Create a 100 byte stuffer */
    EXPECT_SUCCESS(s2n_stuffer_init(&stuffer, &b, &err));

    /* Try to write 51 1-byte ints bytes */
    for (int i = 0; i < 50; i++) {
        uint8_t value = i * (0xff / 50);
        EXPECT_SUCCESS(s2n_stuffer_write_uint8_hex(&stuffer, value, &err));
    }
    EXPECT_FAILURE(s2n_stuffer_write_uint8_hex(&stuffer, 1, &err));

    /* Read those back, and expect the same results */
    for (int i = 0; i < 50; i++) {
        uint8_t value = i * (0xff / 50);
        EXPECT_SUCCESS(s2n_stuffer_read_uint8_hex(&stuffer, &u8, &err));
        EXPECT_EQUAL(u8, value);
    }
    EXPECT_FAILURE(s2n_stuffer_read_uint8_hex(&stuffer, &u8, &err));

    /* Try to write 26 2-byte ints bytes */
    EXPECT_SUCCESS(s2n_stuffer_wipe(&stuffer, &err));
    for (int i = 0; i < 25; i++) {
        uint16_t value = i * (0xffff / 25);
        EXPECT_SUCCESS(s2n_stuffer_write_uint16_hex(&stuffer, value, &err));
    }
    EXPECT_FAILURE(s2n_stuffer_write_uint16_hex(&stuffer, 1, &err));

    /* Read those back, and expect the same results */
    for (int i = 0; i < 25; i++) {
        uint16_t value = i * (0xffff / 25);
        EXPECT_SUCCESS(s2n_stuffer_read_uint16_hex(&stuffer, &u16, &err));
        EXPECT_EQUAL(value, u16);
    }
    EXPECT_FAILURE(s2n_stuffer_read_uint16_hex(&stuffer, &u16, &err));

    /* Try to write 13 4-byte ints bytes */
    EXPECT_SUCCESS(s2n_stuffer_wipe(&stuffer, &err));
    EXPECT_SUCCESS(s2n_stuffer_init(&stuffer, &b, &err));
    for (int i = 0; i < 12; i++) {
        uint32_t value = i * (0xffffffff / 12);
        EXPECT_SUCCESS(s2n_stuffer_write_uint32_hex(&stuffer, value, &err));
    }
    EXPECT_FAILURE(s2n_stuffer_write_uint32_hex(&stuffer, 1, &err));

    /* Read those back, and expect the same results */
    for (int i = 0; i < 12; i++) {
        uint32_t value = i * (0xffffffff / 12);
        EXPECT_SUCCESS(s2n_stuffer_read_uint32_hex(&stuffer, &u32, &err));
        EXPECT_EQUAL(value, u32);
    }
    EXPECT_FAILURE(s2n_stuffer_read_uint32_hex(&stuffer, &u32, &err));

    /* Try to write 7 8-byte ints bytes */
    EXPECT_SUCCESS(s2n_stuffer_wipe(&stuffer, &err));
    for (int i = 0; i < 6; i++) {
        uint64_t value = i * (0xffffffffffffffff / 6);
        EXPECT_SUCCESS(s2n_stuffer_write_uint64_hex(&stuffer, value, &err));
    }
    EXPECT_FAILURE(s2n_stuffer_write_uint64_hex(&stuffer, 1, &err));

    /* Read those back, and expect the same results */
    for (int i = 0; i < 6; i++) {
        uint64_t value = i * (0xffffffffffffffff / 6);
        EXPECT_SUCCESS(s2n_stuffer_read_uint64_hex(&stuffer, &u64, &err));
        EXPECT_EQUAL(value, u64);
    }
    EXPECT_FAILURE(s2n_stuffer_read_uint64_hex(&stuffer, &u64, &err));

    EXPECT_SUCCESS(s2n_stuffer_wipe(&stuffer, &err));
    uint8_t hex[] = "f0F0Zz";
    struct s2n_blob text = {.data = hex,.size = strlen((char *)hex) };
    EXPECT_SUCCESS(s2n_stuffer_write(&stuffer, &text, &err));

    EXPECT_SUCCESS(s2n_stuffer_read_uint8_hex(&stuffer, &u8, &err));
    EXPECT_EQUAL(u8, 240);
    EXPECT_SUCCESS(s2n_stuffer_read_uint8_hex(&stuffer, &u8, &err));
    EXPECT_EQUAL(u8, 240);
    EXPECT_FAILURE(s2n_stuffer_read_uint8_hex(&stuffer, &u8, &err));

    END_TEST();
}
