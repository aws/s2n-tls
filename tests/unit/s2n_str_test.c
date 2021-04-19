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
#include "utils/s2n_str.h"
#include "utils/s2n_blob.h"
#include "utils/s2n_safety.h"

#define BUF_SIZE 10

int main(int argc, char **argv)
{
    BEGIN_TEST();
    EXPECT_SUCCESS(s2n_disable_tls13());

    /* Test s2n_strcpy */
    {
        char buf[BUF_SIZE];
        char *p = buf;
        char *last = buf + BUF_SIZE;
        const char *hello = "Hello";
        const char *world = " World!";
        const char *expect_result = "Hello Wor";
        const char *hi = " Hi!";
        const char *hello_hi = "Hello Hi!";

        p = s2n_strcpy(p, last, hello);
        EXPECT_TRUE(0 == strcmp(buf, hello));

        /* buf = last, string does not change */
        p = s2n_strcpy(p, p, hello);
        EXPECT_TRUE(0 == strcmp(buf, hello));

        /* buf > last, string does not change */
        p = s2n_strcpy(p, buf, hello);
        EXPECT_TRUE(0 == strcmp(buf, hello));

        /* last - buf - 1 <= length of src string, output string length is truncated to buf size - 1 */
        p = s2n_strcpy(p, last, world);
        EXPECT_TRUE(0 == strcmp(buf, expect_result));

        /* NULL src, a NULL terminator should be added */
        p = buf;
        p = s2n_strcpy(p, last, NULL);
        EXPECT_EQUAL(*p, '\0');

        p = s2n_strcpy(p, last, hello);
        EXPECT_TRUE(0 == strcmp(buf, hello));

        /* buf + 1 = last, a NULL terminator should be added */
        *p = 'a';
        p = s2n_strcpy(p, p + 1, hello);
        EXPECT_TRUE(0 == strcmp(buf, hello));

        /* Normal case, string just fit buf size */
        p = s2n_strcpy(p, last, hi);
        EXPECT_TRUE(0 == strcmp(buf, hello_hi));

        /* Writing to the end buf does not change the string */
        s2n_strcpy(p, last, "s2n");
        EXPECT_TRUE(0 == strcmp(buf, hello_hi));
    }

    /* Test s2n_str_hex_to_bytes_length and s2n_str_hex_to_bytes */
    {
        uint8_t test_mem[10] = { 0 };
        uint32_t test_len = 0;

        /* Test with output buffer too small */
        {
            const uint8_t long_input_str[] = "abcdef123456";

            EXPECT_SUCCESS(s2n_str_hex_to_bytes_length(long_input_str, &test_len));
            EXPECT_EQUAL(test_len, sizeof(long_input_str)/2); 

            /* Succeeds with output blob of the right size */
            EXPECT_SUCCESS(s2n_str_hex_to_bytes(long_input_str, test_mem, &test_len));
            test_len -= 1;
            EXPECT_FAILURE_WITH_ERRNO(s2n_str_hex_to_bytes(long_input_str, test_mem, &test_len),
                    S2N_ERR_INSUFFICIENT_MEM_SIZE);
        }

        /* Test with invalid characters */
        {
            EXPECT_SUCCESS(s2n_str_hex_to_bytes_length((const uint8_t*) "12", &test_len));
            EXPECT_SUCCESS(s2n_str_hex_to_bytes((const uint8_t*) "12", test_mem, &test_len));
    
            EXPECT_FAILURE_WITH_ERRNO(s2n_str_hex_to_bytes_length((const uint8_t*) "#2", &test_len),
                    S2N_ERR_INVALID_HEX);
            EXPECT_FAILURE_WITH_ERRNO(s2n_str_hex_to_bytes((const uint8_t*) "#2", test_mem, &test_len),
                    S2N_ERR_INVALID_HEX);

            EXPECT_FAILURE_WITH_ERRNO(s2n_str_hex_to_bytes_length((const uint8_t*) "1#", &test_len),
                    S2N_ERR_INVALID_HEX);
            EXPECT_FAILURE_WITH_ERRNO(s2n_str_hex_to_bytes((const uint8_t*) "1#", test_mem, &test_len),
                    S2N_ERR_INVALID_HEX);
        }

        /* Test with valid characters */
        struct {
            const char *input;
            uint32_t expected_output_size;
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
            test_len = 0;
            EXPECT_SUCCESS(s2n_str_hex_to_bytes_length((const uint8_t *) test_cases[i].input, &test_len));
            EXPECT_SUCCESS(s2n_str_hex_to_bytes((const uint8_t *) test_cases[i].input, test_mem, &test_len));
            EXPECT_BYTEARRAY_EQUAL(test_mem, test_cases[i].expected_output, test_cases[i].expected_output_size);
        }
    }

    END_TEST();
}
