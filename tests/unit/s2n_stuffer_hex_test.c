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
#include "testlib/s2n_testlib.h"

int main(int argc, char **argv)
{
    BEGIN_TEST();

    /* Test: Safety */
    {
        struct s2n_stuffer stuffer = { 0 };
        struct s2n_blob blob = { 0 };

        /* s2n_stuffer_read_hex */
        EXPECT_ERROR_WITH_ERRNO(s2n_stuffer_read_hex(&stuffer, NULL), S2N_ERR_NULL);
        EXPECT_ERROR_WITH_ERRNO(s2n_stuffer_read_hex(NULL, &blob), S2N_ERR_NULL);

        /* s2n_stuffer_write_hex */
        EXPECT_ERROR_WITH_ERRNO(s2n_stuffer_write_hex(&stuffer, NULL), S2N_ERR_NULL);
        EXPECT_ERROR_WITH_ERRNO(s2n_stuffer_write_hex(NULL, &blob), S2N_ERR_NULL);

        /* s2n_stuffer_read_uint8_hex */
        uint8_t value_u8 = 0;
        EXPECT_ERROR_WITH_ERRNO(s2n_stuffer_read_uint8_hex(&stuffer, NULL), S2N_ERR_NULL);
        EXPECT_ERROR_WITH_ERRNO(s2n_stuffer_read_uint8_hex(NULL, &value_u8), S2N_ERR_NULL);

        /* s2n_stuffer_write_uint8_hex */
        EXPECT_ERROR_WITH_ERRNO(s2n_stuffer_write_uint8_hex(NULL, 0), S2N_ERR_NULL);

        /* s2n_stuffer_read_uint16_hex */
        uint16_t value_u16 = 0;
        EXPECT_ERROR_WITH_ERRNO(s2n_stuffer_read_uint16_hex(&stuffer, NULL), S2N_ERR_NULL);
        EXPECT_ERROR_WITH_ERRNO(s2n_stuffer_read_uint16_hex(NULL, &value_u16), S2N_ERR_NULL);

        /* s2n_stuffer_write_uint16_hex */
        EXPECT_ERROR_WITH_ERRNO(s2n_stuffer_write_uint16_hex(NULL, 0), S2N_ERR_NULL);
    }

    /* Test hex with uint8 */
    {
        const size_t expected_size = 2;
        struct {
            const uint8_t num;
            const char *hex;
        } test_cases[] = {
            /* Test first digit */
            { .num = 0, .hex = "00" },
            { .num = 1, .hex = "01" },
            { .num = 5, .hex = "05" },
            { .num = 15, .hex = "0f" },
            /* Test second digit */
            { .num = 0x10, .hex = "10" },
            { .num = 0x50, .hex = "50" },
            { .num = 0xf0, .hex = "f0" },
            /* Test all numbers */
            { .num = 0x12, .hex = "12" },
            { .num = 0x34, .hex = "34" },
            { .num = 0x56, .hex = "56" },
            { .num = 0x78, .hex = "78" },
            { .num = 0x90, .hex = "90" },
            /* Test all letters */
            { .num = 0xab, .hex = "ab" },
            { .num = 0xcd, .hex = "cd" },
            { .num = 0xef, .hex = "ef" },
            /* Test mix of numbers and letters */
            { .num = 0x1a, .hex = "1a" },
            { .num = 0x9f, .hex = "9f" },
            /* Test high values */
            { .num = UINT8_MAX - 1, .hex = "fe" },
            { .num = UINT8_MAX, .hex = "ff" },
        };
        for (size_t i = 0; i < s2n_array_len(test_cases); i++) {
            /* Test s2n_stuffer_write_uint8_hex */
            {
                DEFER_CLEANUP(struct s2n_stuffer hex = { 0 }, s2n_stuffer_free);
                EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&hex, 0));
                EXPECT_OK(s2n_stuffer_write_uint8_hex(&hex, test_cases[i].num));

                size_t actual_size = s2n_stuffer_data_available(&hex);
                EXPECT_EQUAL(actual_size, expected_size);
                EXPECT_EQUAL(strlen(test_cases[i].hex), expected_size);

                const char *actual_hex = s2n_stuffer_raw_read(&hex, actual_size);
                EXPECT_BYTEARRAY_EQUAL(actual_hex, test_cases[i].hex, actual_size);
            };

            /* Test s2n_stuffer_read_uint8_hex */
            {
                DEFER_CLEANUP(struct s2n_stuffer hex = { 0 }, s2n_stuffer_free);
                EXPECT_SUCCESS(s2n_stuffer_alloc(&hex, expected_size));
                EXPECT_SUCCESS(s2n_stuffer_write_text(&hex, test_cases[i].hex, expected_size));

                uint8_t actual_num = 0;
                EXPECT_OK(s2n_stuffer_read_uint8_hex(&hex, &actual_num));
                EXPECT_EQUAL(actual_num, test_cases[i].num);
                EXPECT_FALSE(s2n_stuffer_data_available(&hex));
            };

            /* Test s2n_stuffer_write_hex */
            {
                DEFER_CLEANUP(struct s2n_stuffer num_in = { 0 }, s2n_stuffer_free);
                EXPECT_SUCCESS(s2n_stuffer_alloc(&num_in, sizeof(uint8_t)));
                EXPECT_SUCCESS(s2n_stuffer_write_uint8(&num_in, test_cases[i].num));

                DEFER_CLEANUP(struct s2n_stuffer hex_out = { 0 }, s2n_stuffer_free);
                EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&hex_out, 0));
                EXPECT_OK(s2n_stuffer_write_hex(&hex_out, &num_in.blob));

                size_t actual_size = s2n_stuffer_data_available(&hex_out);
                EXPECT_EQUAL(actual_size, expected_size);
                EXPECT_EQUAL(strlen(test_cases[i].hex), expected_size);

                const char *actual_hex = s2n_stuffer_raw_read(&hex_out, actual_size);
                EXPECT_BYTEARRAY_EQUAL(actual_hex, test_cases[i].hex, actual_size);
            };

            /* Test s2n_stuffer_read_hex */
            {
                DEFER_CLEANUP(struct s2n_stuffer hex_in = { 0 }, s2n_stuffer_free);
                EXPECT_SUCCESS(s2n_stuffer_alloc(&hex_in, expected_size));
                EXPECT_SUCCESS(s2n_stuffer_write_text(&hex_in, test_cases[i].hex, expected_size));

                uint8_t actual_num = 0;
                struct s2n_blob num_out = { 0 };
                EXPECT_SUCCESS(s2n_blob_init(&num_out, &actual_num, 1));
                EXPECT_OK(s2n_stuffer_read_hex(&hex_in, &num_out));
                EXPECT_EQUAL(actual_num, test_cases[i].num);
                EXPECT_FALSE(s2n_stuffer_data_available(&hex_in));
            };
        }
    };

    /* Test hex with uint16 */
    {
        const size_t expected_size = 4;
        struct {
            uint16_t num;
            const char *hex;
        } test_cases[] = {
            /* Test first digit */
            { .num = 0, .hex = "0000" },
            { .num = 1, .hex = "0001" },
            { .num = 5, .hex = "0005" },
            { .num = 15, .hex = "000f" },
            /* Test second digit */
            { .num = 0x10, .hex = "0010" },
            { .num = 0x50, .hex = "0050" },
            { .num = 0xf0, .hex = "00f0" },
            /* Test third digit */
            { .num = 0x0100, .hex = "0100" },
            { .num = 0x0500, .hex = "0500" },
            { .num = 0x0f00, .hex = "0f00" },
            /* Test fourth digit */
            { .num = 0x1000, .hex = "1000" },
            { .num = 0x5000, .hex = "5000" },
            { .num = 0xf000, .hex = "f000" },
            /* Test all numbers */
            { .num = 0x1234, .hex = "1234" },
            { .num = 0x5678, .hex = "5678" },
            { .num = 0x9012, .hex = "9012" },
            /* Test all letters */
            { .num = 0xabcd, .hex = "abcd" },
            { .num = 0xefab, .hex = "efab" },
            /* Test mix of numbers and letters */
            { .num = 0x1a2b, .hex = "1a2b" },
            { .num = 0x8e9f, .hex = "8e9f" },
            /* Test high values */
            { .num = UINT16_MAX - 1, .hex = "fffe" },
            { .num = UINT16_MAX, .hex = "ffff" },
        };
        for (size_t i = 0; i < s2n_array_len(test_cases); i++) {
            /* Test s2n_stuffer_write_uint16_hex */
            {
                DEFER_CLEANUP(struct s2n_stuffer hex = { 0 }, s2n_stuffer_free);
                EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&hex, 0));
                EXPECT_OK(s2n_stuffer_write_uint16_hex(&hex, test_cases[i].num));

                size_t actual_size = s2n_stuffer_data_available(&hex);
                EXPECT_EQUAL(actual_size, expected_size);
                EXPECT_EQUAL(strlen(test_cases[i].hex), expected_size);

                const char *actual_hex = s2n_stuffer_raw_read(&hex, actual_size);
                EXPECT_BYTEARRAY_EQUAL(actual_hex, test_cases[i].hex, actual_size);
            };

            /* Test s2n_stuffer_read_uint16_hex */
            {
                DEFER_CLEANUP(struct s2n_stuffer hex = { 0 }, s2n_stuffer_free);
                EXPECT_SUCCESS(s2n_stuffer_alloc(&hex, expected_size));
                EXPECT_SUCCESS(s2n_stuffer_write_text(&hex, test_cases[i].hex, expected_size));

                uint16_t actual_num = 0;
                EXPECT_OK(s2n_stuffer_read_uint16_hex(&hex, &actual_num));
                EXPECT_EQUAL(actual_num, test_cases[i].num);
                EXPECT_FALSE(s2n_stuffer_data_available(&hex));
            };

            /* Test s2n_stuffer_write_hex */
            {
                DEFER_CLEANUP(struct s2n_stuffer num_in = { 0 }, s2n_stuffer_free);
                EXPECT_SUCCESS(s2n_stuffer_alloc(&num_in, sizeof(uint16_t)));
                EXPECT_SUCCESS(s2n_stuffer_write_uint16(&num_in, test_cases[i].num));

                DEFER_CLEANUP(struct s2n_stuffer hex_out = { 0 }, s2n_stuffer_free);
                EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&hex_out, 0));
                EXPECT_OK(s2n_stuffer_write_hex(&hex_out, &num_in.blob));

                size_t actual_size = s2n_stuffer_data_available(&hex_out);
                EXPECT_EQUAL(actual_size, expected_size);
                EXPECT_EQUAL(strlen(test_cases[i].hex), expected_size);

                const char *actual_hex = s2n_stuffer_raw_read(&hex_out, actual_size);
                EXPECT_BYTEARRAY_EQUAL(actual_hex, test_cases[i].hex, actual_size);
            };

            /* Test s2n_stuffer_read_hex */
            {
                DEFER_CLEANUP(struct s2n_stuffer hex_in = { 0 }, s2n_stuffer_free);
                EXPECT_SUCCESS(s2n_stuffer_alloc(&hex_in, expected_size));
                EXPECT_SUCCESS(s2n_stuffer_write_text(&hex_in, test_cases[i].hex, expected_size));

                DEFER_CLEANUP(struct s2n_stuffer num_out = { 0 }, s2n_stuffer_free);
                EXPECT_SUCCESS(s2n_stuffer_alloc(&num_out, sizeof(uint16_t)));
                EXPECT_OK(s2n_stuffer_read_hex(&hex_in, &num_out.blob));
                EXPECT_SUCCESS(s2n_stuffer_skip_write(&num_out, num_out.blob.size));
                EXPECT_FALSE(s2n_stuffer_data_available(&hex_in));

                uint16_t actual_num = 0;
                EXPECT_SUCCESS(s2n_stuffer_read_uint16(&num_out, &actual_num));
                EXPECT_EQUAL(actual_num, test_cases[i].num);
                EXPECT_FALSE(s2n_stuffer_data_available(&num_out));
            };
        }
    };

    /* Test longer series of bytes */
    {
        struct {
            uint8_t bytes[50];
            uint8_t bytes_size;
            const char *hex;
        } test_cases[] = {
            /* clang-format off */
            {
                .bytes = { 0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef },
                .bytes_size = 8,
                .hex = "1234567890abcdef",
            },
            {
                .bytes = { 0 },
                .bytes_size = 4,
                .hex = "00000000",
            },
            {
                .bytes = { 0xff, 0x11, 0x22, 0x55, 0xaa },
                .bytes_size = 5,
                .hex = "ff112255aa",
            },
            {
                .bytes = { 0x10, 0x10, 0x10, 0x10 },
                .bytes_size = 4,
                .hex = "10101010",
            },
            {
                .bytes = { 0x00, 0x00, 0x01 },
                .bytes_size = 3,
                .hex = "000001",
            },
            {
                .bytes = { 0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef },
                .bytes_size = 16,
                .hex = "1234567890abcdef"
                       "0000000000000000",
            },
            {
                .bytes = {
                    0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef,
                    0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0x01,
                    0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0x02,
                    0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0x03,
                },
                .bytes_size = 8 * 4,
                .hex =
                    "1234567890abcdef"
                    "1234567890abcd01"
                    "1234567890abcd02"
                    "1234567890abcd03",
            },
            /* clang-format on */
        };

        for (size_t i = 0; i < s2n_array_len(test_cases); i++) {
            size_t hex_size = strlen(test_cases[i].hex);
            EXPECT_EQUAL(test_cases[i].bytes_size * 2, hex_size);

            /* Test s2n_stuffer_write_hex */
            {
                DEFER_CLEANUP(struct s2n_stuffer num_in = { 0 }, s2n_stuffer_free);
                EXPECT_SUCCESS(s2n_stuffer_alloc(&num_in, test_cases[i].bytes_size));
                EXPECT_SUCCESS(s2n_stuffer_write_bytes(&num_in,
                        test_cases[i].bytes, test_cases[i].bytes_size));

                DEFER_CLEANUP(struct s2n_stuffer hex_out = { 0 }, s2n_stuffer_free);
                EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&hex_out, 0));
                EXPECT_OK(s2n_stuffer_write_hex(&hex_out, &num_in.blob));

                size_t actual_size = s2n_stuffer_data_available(&hex_out);
                EXPECT_EQUAL(actual_size, hex_size);

                const char *actual_hex = s2n_stuffer_raw_read(&hex_out, actual_size);
                EXPECT_BYTEARRAY_EQUAL(actual_hex, test_cases[i].hex, actual_size);
            };

            /* Test s2n_stuffer_read_hex */
            {
                DEFER_CLEANUP(struct s2n_stuffer hex_in = { 0 }, s2n_stuffer_free);
                EXPECT_SUCCESS(s2n_stuffer_alloc(&hex_in, hex_size));
                EXPECT_SUCCESS(s2n_stuffer_write_text(&hex_in, test_cases[i].hex, hex_size));

                DEFER_CLEANUP(struct s2n_blob num_out = { 0 }, s2n_free);
                EXPECT_SUCCESS(s2n_alloc(&num_out, test_cases[i].bytes_size));
                EXPECT_OK(s2n_stuffer_read_hex(&hex_in, &num_out));
                EXPECT_BYTEARRAY_EQUAL(num_out.data, test_cases[i].bytes, test_cases[i].bytes_size);
                EXPECT_FALSE(s2n_stuffer_data_available(&hex_in));
            };
        }
    };

    /* Test bad hex string */
    {
        /* Test bad uint8 hex */
        {
            const char *test_hexes[] = {
                /* clang-format off */
                /* one good hex as a control */
                "FFFFFF",
                /* too short */
                "", "0", "1",
                /* invalid characters: symbols <'0' */
                "0/", "!0",
                /* invalid characters: symbols >'9', <'A' */
                "0:", "@0",
                /* invalid characters: symbols >'Z', <'a' */
                "0[", "`0",
                /* invalid characters: symbols >'z' */
                "0{", "~0",
                /* invalid characters: non-hex letters */
                "0g", "z0", "0G", "Z0",
                /* clang-format on */
            };

            for (size_t i = 0; i < s2n_array_len(test_hexes); i++) {
                const char *test_hex = test_hexes[i];

                /* Test s2n_stuffer_read_uint8_hex */
                {
                    DEFER_CLEANUP(struct s2n_stuffer hex = { 0 }, s2n_stuffer_free);
                    EXPECT_SUCCESS(s2n_stuffer_alloc(&hex, strlen(test_hex)));
                    EXPECT_SUCCESS(s2n_stuffer_write_str(&hex, test_hex));

                    uint8_t actual_num = 0;
                    if (i == 0) {
                        EXPECT_OK(s2n_stuffer_read_uint8_hex(&hex, &actual_num));
                    } else {
                        EXPECT_ERROR_WITH_ERRNO(
                                s2n_stuffer_read_uint8_hex(&hex, &actual_num),
                                S2N_ERR_BAD_HEX);
                    }
                };

                /* Test s2n_stuffer_read_hex */
                {
                    DEFER_CLEANUP(struct s2n_stuffer hex = { 0 }, s2n_stuffer_free);
                    EXPECT_SUCCESS(s2n_stuffer_alloc(&hex, strlen(test_hex)));
                    EXPECT_SUCCESS(s2n_stuffer_write_str(&hex, test_hex));

                    DEFER_CLEANUP(struct s2n_blob out = { 0 }, s2n_free);
                    EXPECT_SUCCESS(s2n_alloc(&out, sizeof(uint8_t)));
                    if (i == 0) {
                        EXPECT_OK(s2n_stuffer_read_hex(&hex, &out));
                    } else {
                        EXPECT_ERROR_WITH_ERRNO(
                                s2n_stuffer_read_hex(&hex, &out),
                                S2N_ERR_BAD_HEX);
                    }
                };
            }
        };

        /* Test bad uint16 hex */
        {
            const char *test_hexes[] = {
                /* clang-format off */
                /* one good hex as a control */
                "FFFFFF",
                /* too short */
                "", "0", "1", "00", "01", "000", "001",
                /* invalid characters: symbols <'0' */
                "000/", "00!0", "0.00", "#000",
                /* invalid characters: symbols >'9', <'A' */
                "000:", "00@0", "0?00", ";000",
                /* invalid characters: symbols >'Z', <'a' */
                "000[", "00`0", "0_00", "^000",
                /* invalid characters: symbols >'z' */
                "000{", "00~0", "0}00", "|000",
                /* invalid characters: non-hex letters */
                "000g", "00z0", "000G", "00Z0", "0Y00", "S000",
                /* clang-format on */
            };

            for (size_t i = 0; i < s2n_array_len(test_hexes); i++) {
                const char *test_hex = test_hexes[i];

                /* Test s2n_stuffer_read_uint16_hex */
                {
                    DEFER_CLEANUP(struct s2n_stuffer hex = { 0 }, s2n_stuffer_free);
                    EXPECT_SUCCESS(s2n_stuffer_alloc(&hex, strlen(test_hex)));
                    EXPECT_SUCCESS(s2n_stuffer_write_str(&hex, test_hex));

                    uint16_t actual_num = 0;
                    if (i == 0) {
                        EXPECT_OK(s2n_stuffer_read_uint16_hex(&hex, &actual_num));
                    } else {
                        EXPECT_ERROR_WITH_ERRNO(
                                s2n_stuffer_read_uint16_hex(&hex, &actual_num),
                                S2N_ERR_BAD_HEX);
                    }
                };

                /* Test s2n_stuffer_read_hex */
                {
                    DEFER_CLEANUP(struct s2n_stuffer hex = { 0 }, s2n_stuffer_free);
                    EXPECT_SUCCESS(s2n_stuffer_alloc(&hex, strlen(test_hex)));
                    EXPECT_SUCCESS(s2n_stuffer_write_str(&hex, test_hex));

                    DEFER_CLEANUP(struct s2n_blob out = { 0 }, s2n_free);
                    EXPECT_SUCCESS(s2n_alloc(&out, sizeof(uint16_t)));
                    if (i == 0) {
                        EXPECT_OK(s2n_stuffer_read_hex(&hex, &out));
                    } else {
                        EXPECT_ERROR_WITH_ERRNO(
                                s2n_stuffer_read_hex(&hex, &out),
                                S2N_ERR_BAD_HEX);
                    }
                };
            }
        };
    }

    /* Test converting to and from all uint8_t */
    for (size_t i = 0; i <= UINT8_MAX; i++) {
        DEFER_CLEANUP(struct s2n_stuffer hex = { 0 }, s2n_stuffer_free);
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&hex, 0));
        EXPECT_OK(s2n_stuffer_write_uint8_hex(&hex, i));

        uint8_t value = 0;
        EXPECT_OK(s2n_stuffer_read_uint8_hex(&hex, &value));
        EXPECT_EQUAL(value, i);
    }

    /* Test converting to and from all uint16_t */
    for (size_t i = 0; i <= UINT16_MAX; i++) {
        DEFER_CLEANUP(struct s2n_stuffer hex = { 0 }, s2n_stuffer_free);
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&hex, 0));
        EXPECT_OK(s2n_stuffer_write_uint16_hex(&hex, i));

        uint16_t value = 0;
        EXPECT_OK(s2n_stuffer_read_uint16_hex(&hex, &value));
        EXPECT_EQUAL(value, i);
    }

    /* Test reading and writing multiple values with different methods */
    {
        const uint8_t values_u8[] = {
            /* clang-format off */
            0x00, 0x01, 0x02, 0x03, 0x04, 0x00,
            0x12, 0x34, 0x56, 0x78, 0x90, 0x00,
            0xab, 0xbc, 0xcd, 0xde, 0xef, 0x00,
            /* clang-format on */
        };
        const uint16_t values_u16[] = {
            /* clang-format off */
            0x0001, 0x0203, 0x0400,
            0x1234, 0x5678, 0x9000,
            0xabbc, 0xcdde, 0xef00,
            /* clang-format on */
        };
        const size_t bytes_size = sizeof(values_u8);
        const char hex_str[] =
                "000102030400"
                "123456789000"
                "abbccddeef00";

        enum s2n_test_hex_method {
            S2N_TEST_U8 = 0,
            S2N_TEST_U16,
            S2N_TEST_N,
            S2N_TEST_HEX_METHOD_COUNT
        };

        for (size_t writer_i = 0; writer_i < S2N_TEST_HEX_METHOD_COUNT; writer_i++) {
            for (size_t reader_i = 0; reader_i < S2N_TEST_HEX_METHOD_COUNT; reader_i++) {
                DEFER_CLEANUP(struct s2n_stuffer hex = { 0 }, s2n_stuffer_free);
                EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&hex, 0));

                if (writer_i == S2N_TEST_U8) {
                    for (size_t i = 0; i < sizeof(values_u8); i++) {
                        EXPECT_OK(s2n_stuffer_write_uint8_hex(&hex, values_u8[i]));
                    }
                } else if (writer_i == S2N_TEST_U16) {
                    for (size_t i = 0; i < s2n_array_len(values_u16); i++) {
                        EXPECT_OK(s2n_stuffer_write_uint16_hex(&hex, values_u16[i]));
                    }
                } else if (writer_i == S2N_TEST_N) {
                    DEFER_CLEANUP(struct s2n_stuffer input = { 0 }, s2n_stuffer_free);
                    EXPECT_SUCCESS(s2n_stuffer_alloc(&input, bytes_size));
                    EXPECT_SUCCESS(s2n_stuffer_write_bytes(&input, values_u8, bytes_size));

                    EXPECT_OK(s2n_stuffer_write_hex(&hex, &input.blob));
                } else {
                    FAIL_MSG("unknown hex method");
                }

                size_t written = s2n_stuffer_data_available(&hex);
                EXPECT_EQUAL(written, strlen(hex_str));
                EXPECT_BYTEARRAY_EQUAL(hex_str, hex.blob.data, written);

                if (reader_i == S2N_TEST_U8) {
                    for (size_t i = 0; i < sizeof(values_u8); i++) {
                        uint8_t byte = 0;
                        EXPECT_OK(s2n_stuffer_read_uint8_hex(&hex, &byte));
                        EXPECT_EQUAL(byte, values_u8[i]);
                    }
                    EXPECT_FALSE(s2n_stuffer_data_available(&hex));
                } else if (reader_i == S2N_TEST_U16) {
                    for (size_t i = 0; i < s2n_array_len(values_u16); i++) {
                        uint16_t value = 0;
                        EXPECT_OK(s2n_stuffer_read_uint16_hex(&hex, &value));
                        EXPECT_EQUAL(value, values_u16[i]);
                    }
                    EXPECT_FALSE(s2n_stuffer_data_available(&hex));
                } else if (reader_i == S2N_TEST_N) {
                    DEFER_CLEANUP(struct s2n_blob output = { 0 }, s2n_free);
                    EXPECT_SUCCESS(s2n_alloc(&output, sizeof(values_u8)));
                    EXPECT_OK(s2n_stuffer_read_hex(&hex, &output));
                    EXPECT_EQUAL(s2n_stuffer_data_available(&hex), 0);
                    EXPECT_BYTEARRAY_EQUAL(values_u8, output.data, output.size);
                } else {
                    FAIL_MSG("unknown hex method");
                }
            }
        }
    };

    END_TEST();
}
