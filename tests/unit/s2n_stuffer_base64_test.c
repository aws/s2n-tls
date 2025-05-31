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

#include <string.h>

#include "api/s2n.h"
#include "s2n_test.h"
#include "stuffer/s2n_stuffer.h"
#include "utils/s2n_random.h"

/* Generated with this python:
 *
 * b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
 *
 * for i in range(0, 256):
 *     if chr(i) in b64:
 *         print str(b64.index(chr(i))) + ", ",
 *      else:
 *         print "255, ",
 *
 *      if (i + 1) % 16 == 0:
 *          print
 *
 * Note that '=' maps to 64.
 */
static const uint8_t b64_inverse[256] = { 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 62, 255, 255, 255, 63, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 255, 255, 255, 64, 255, 255,
    255, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 255, 255, 255,
    255, 255, 255, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50,
    51, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255 };

bool s2n_is_base64_char_alternate(unsigned char c)
{
    return (b64_inverse[*((uint8_t *) (&c))] != 255);
}

int main(int argc, char **argv)
{
    BEGIN_TEST();

    /* s2n_is_base64_char */
    for (uint8_t i = 0; i < 255; i++) {
        EXPECT_EQUAL(s2n_is_base64_char(i), s2n_is_base64_char_alternate(i));
    };

    /* safety: s2n_stuffer_read/write_base64 */
    {
        struct s2n_stuffer a = { 0 };
        struct s2n_stuffer b = { 0 };
        EXPECT_SUCCESS(s2n_stuffer_write_base64(&a, &b));
        EXPECT_SUCCESS(s2n_stuffer_read_base64(&a, &b));
    }

    /* known-value base64 read/write tests using byte strings of `0` */
    struct {
        uint8_t bytes;
        const char *expected;
    } test_cases[] = {
        {
                .bytes = 1,
                .expected = "AA==",
        },
        {
                .bytes = 2,
                .expected = "AAA=",
        },
        {
                .bytes = 3,
                .expected = "AAAA",
        },
        {
                .bytes = 4,
                .expected = "AAAAAA==",
        },
    };
    for (int i = 0; i < s2n_array_len(test_cases); i++) {
        DEFER_CLEANUP(struct s2n_stuffer binary = { 0 }, s2n_stuffer_free);
        DEFER_CLEANUP(struct s2n_stuffer base64 = { 0 }, s2n_stuffer_free);
        DEFER_CLEANUP(struct s2n_stuffer mirror = { 0 }, s2n_stuffer_free);

        uint32_t base64_groups = test_cases[i].bytes / 3;
        if (test_cases[i].bytes % 3 != 0) {
            base64_groups++;
        }
        EXPECT_SUCCESS(s2n_stuffer_alloc(&binary, test_cases[i].bytes));
        /* +1 for null terminator */
        EXPECT_SUCCESS(s2n_stuffer_alloc(&base64, base64_groups * 4 + 1));
        EXPECT_SUCCESS(s2n_stuffer_alloc(&mirror, base64_groups * 3));

        for (int b = 0; b < test_cases[i].bytes; b++) {
            EXPECT_SUCCESS(s2n_stuffer_write_uint8(&binary, 0));
        }

        EXPECT_SUCCESS(s2n_stuffer_write_base64(&base64, &binary));
        EXPECT_EQUAL(s2n_stuffer_data_available(&base64), strlen(test_cases[i].expected));
        EXPECT_BYTEARRAY_EQUAL(base64.blob.data, test_cases[i].expected, strlen(test_cases[i].expected));

        EXPECT_SUCCESS(s2n_stuffer_read_base64(&base64, &mirror));
        EXPECT_EQUAL(s2n_stuffer_data_available(&mirror), test_cases[i].bytes);
        EXPECT_BYTEARRAY_EQUAL(binary.blob.data, mirror.blob.data, test_cases[i].bytes);
    };

    char hello_world[] = "Hello world!";
    uint8_t hello_world_base64[] = "SGVsbG8gd29ybGQhAA==";
    struct s2n_stuffer stuffer = { 0 }, known_data = { 0 }, scratch = { 0 }, entropy = { 0 }, mirror = { 0 };
    uint8_t pad[50];
    struct s2n_blob r = { 0 };
    EXPECT_OK(s2n_blob_init(&r, pad, sizeof(pad)));

    /* Create a 100 byte stuffer */
    EXPECT_SUCCESS(s2n_stuffer_alloc(&stuffer, 1000));

    /* Write our known data */
    EXPECT_SUCCESS(s2n_stuffer_alloc_ro_from_string(&known_data, hello_world));
    EXPECT_SUCCESS(s2n_stuffer_write_base64(&stuffer, &known_data));
    EXPECT_SUCCESS(s2n_stuffer_free(&known_data));

    /* Check it against the known output */
    EXPECT_EQUAL(memcmp(stuffer.blob.data, hello_world_base64, strlen((char *) hello_world)), 0);

    /* Check that we can read it again */
    EXPECT_SUCCESS(s2n_stuffer_alloc(&scratch, 50));
    EXPECT_SUCCESS(s2n_stuffer_read_base64(&stuffer, &scratch));
    EXPECT_SUCCESS(memcmp(scratch.blob.data, hello_world, strlen(hello_world)));

    /* Now try with some randomly generated data. Make sure we try each boundary case,
     * where size % 3 == 0, 1, 2
     */
    EXPECT_SUCCESS(s2n_stuffer_alloc(&entropy, 50));
    /* +1 to give space for the null terminator written by EVP_EncodeBlock */
    EXPECT_SUCCESS(s2n_stuffer_alloc(&mirror, 50 + 1));

    for (size_t i = entropy.blob.size; i > 0; i--) {
        EXPECT_SUCCESS(s2n_stuffer_wipe(&stuffer));
        EXPECT_SUCCESS(s2n_stuffer_wipe(&entropy));
        EXPECT_SUCCESS(s2n_stuffer_wipe(&mirror));

        /* Get i bytes of random data */
        r.size = i;
        EXPECT_OK(s2n_get_public_random_data(&r));
        EXPECT_SUCCESS(s2n_stuffer_write_bytes(&entropy, pad, i));

        /* Write i bytes  it, base64 encoded */
        /* Read it back, decoded */
        EXPECT_SUCCESS(s2n_stuffer_write_base64(&stuffer, &entropy));

        /* s2n_is_base64_char: should be true for all bytes in the stuffer */
        while (s2n_stuffer_data_available(&stuffer) > 0) {
            uint8_t byte = 0;
            EXPECT_SUCCESS(s2n_stuffer_read_uint8(&stuffer, &byte));
            EXPECT_TRUE(s2n_is_base64_char(byte));
        }
        EXPECT_SUCCESS(s2n_stuffer_reread(&stuffer));

        /* Should be (i / 3) * 4 + a carry  */
        EXPECT_EQUAL((i / 3) * 4 + ((i % 3) ? 4 : 0), s2n_stuffer_data_available(&stuffer));

        /* Read it back, decoded */
        EXPECT_SUCCESS(s2n_stuffer_read_base64(&stuffer, &mirror));

        /* Verify it's the same */
        EXPECT_EQUAL(memcmp(mirror.blob.data, entropy.blob.data, i), 0);
    }

    EXPECT_SUCCESS(s2n_stuffer_free(&stuffer));
    EXPECT_SUCCESS(s2n_stuffer_free(&scratch));
    EXPECT_SUCCESS(s2n_stuffer_free(&mirror));
    EXPECT_SUCCESS(s2n_stuffer_free(&entropy));

    END_TEST();
}
