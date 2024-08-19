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

#include "api/unstable/fingerprint.h"
#include "s2n_test.h"
#include "testlib/s2n_testlib.h"
#include "tls/s2n_tls.h"

#define S2N_TEST_OUTPUT_SIZE 200

#define S2N_TEST_CLIENT_HELLO_VERSION \
    0x00, 0x00

/* clang-format off */
#define S2N_TEST_CLIENT_HELLO_AFTER_VERSION \
    /* random */ \
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
    /* session id */ \
    0x00
/* clang-format on */

/* clang-format off */
#define S2N_TEST_CLIENT_HELLO_CIPHERS \
    /* cipher suites size */ \
    0x00, 0x02, \
    /* cipher suites */ \
    0x00, 0x00
/* clang-format on */

#define S2N_TEST_CLIENT_HELLO_AFTER_CIPHERS \
    /* legacy compression methods */        \
    0x01, 0x00

#define S2N_TEST_CLIENT_HELLO_EMPTY_EXTENSIONS \
    0x00, 0x00
#define S2N_TEST_CLIENT_HELLO_EMPTY_EXTENSION \
    0x00, 0x00

/* This macro currently assumes that the message size is only one byte (<=255). */
#define S2N_INIT_CLIENT_HELLO(name, ...)                 \
    uint8_t _##name##_message[] = { __VA_ARGS__ };       \
    EXPECT_TRUE(sizeof(_##name##_message) <= UINT8_MAX); \
    uint8_t name[] = {                                   \
        TLS_CLIENT_HELLO,                                \
        0x00, 0x00, sizeof(_##name##_message),           \
        __VA_ARGS__                                      \
    }

/* clang-format off */
#define S2N_INIT_CLIENT_HELLO_WITH_EXTENSION(name, extension) \
    S2N_INIT_CLIENT_HELLO(name, \
        S2N_TEST_CLIENT_HELLO_VERSION, \
        S2N_TEST_CLIENT_HELLO_AFTER_VERSION, \
        S2N_TEST_CLIENT_HELLO_CIPHERS, \
        S2N_TEST_CLIENT_HELLO_AFTER_CIPHERS, \
        /* extensions size */ \
        0x00, 0x04, \
        /* extension */ \
        0x00, extension, S2N_TEST_CLIENT_HELLO_EMPTY_EXTENSION \
    )
/* clang-format on */

enum {
    S2N_JA4_A_PROTOCOL = 0,
    S2N_JA4_A_VERSION_1,
    S2N_JA4_A_VERSION_2,
    S2N_JA4_A_DEST,
    S2N_JA4_A_CIPHER_COUNT_1,
    S2N_JA4_A_CIPHER_COUNT_2,
    S2N_JA4_A_EXT_COUNT_1,
    S2N_JA4_A_EXT_COUNT_2,
    S2N_JA4_A_ALPN_FIRST,
    S2N_JA4_A_ALPN_LAST,
    S2N_JA4_A_SIZE
} s2n_ja4_a_fields;
#define S2N_JA4_B_START      (S2N_JA4_A_SIZE + 1)
#define S2N_JA4_C_HASH_START (S2N_JA4_B_START + 12 + 1)
/* This assumes a single ciphers suite / use of S2N_TEST_CLIENT_HELLO_CIPHERS */
#define S2N_JA4_C_RAW_START (S2N_JA4_B_START + 4 + 1)

static S2N_RESULT s2n_test_ja4_hash_from_bytes(
        uint8_t *client_hello_bytes, size_t client_hello_bytes_size,
        size_t max_hash_size, uint8_t *hash, uint32_t *hash_size)
{
    DEFER_CLEANUP(struct s2n_client_hello *client_hello = NULL, s2n_client_hello_free);
    client_hello = s2n_client_hello_parse_message(client_hello_bytes, client_hello_bytes_size);
    RESULT_GUARD_PTR(client_hello);

    DEFER_CLEANUP(struct s2n_fingerprint *fingerprint = NULL, s2n_fingerprint_free);
    fingerprint = s2n_fingerprint_new(S2N_FINGERPRINT_JA4);
    RESULT_GUARD_PTR(fingerprint);
    RESULT_GUARD_POSIX(s2n_fingerprint_set_client_hello(fingerprint, client_hello));

    RESULT_GUARD_POSIX(s2n_fingerprint_get_hash(fingerprint,
            max_hash_size, hash, hash_size));
    return S2N_RESULT_OK;
}

static S2N_RESULT s2n_test_ja4_raw_from_bytes(
        uint8_t *client_hello_bytes, size_t client_hello_bytes_size,
        size_t max_output_size, uint8_t *output, uint32_t *output_size)
{
    DEFER_CLEANUP(struct s2n_client_hello *client_hello = NULL, s2n_client_hello_free);
    client_hello = s2n_client_hello_parse_message(client_hello_bytes, client_hello_bytes_size);
    RESULT_GUARD_PTR(client_hello);

    DEFER_CLEANUP(struct s2n_fingerprint *fingerprint = NULL, s2n_fingerprint_free);
    fingerprint = s2n_fingerprint_new(S2N_FINGERPRINT_JA4);
    RESULT_GUARD_PTR(fingerprint);
    RESULT_GUARD_POSIX(s2n_fingerprint_set_client_hello(fingerprint, client_hello));

    RESULT_GUARD_POSIX(s2n_fingerprint_get_raw(fingerprint,
            max_output_size, output, output_size));
    return S2N_RESULT_OK;
}

static S2N_RESULT s2n_test_ja4_hash_from_cipher_count(uint16_t cipher_count,
        size_t max_hash_size, uint8_t *hash, uint32_t *hash_size)
{
    DEFER_CLEANUP(struct s2n_stuffer bytes = { 0 }, s2n_stuffer_free);
    RESULT_GUARD_POSIX(s2n_stuffer_growable_alloc(&bytes, 100));

    struct s2n_stuffer_reservation message_size = { 0 };
    RESULT_GUARD_POSIX(s2n_stuffer_write_uint8(&bytes, TLS_CLIENT_HELLO));
    RESULT_GUARD_POSIX(s2n_stuffer_reserve_uint24(&bytes, &message_size));

    uint8_t before_ciphers[] = {
        S2N_TEST_CLIENT_HELLO_VERSION,
        S2N_TEST_CLIENT_HELLO_AFTER_VERSION,
    };
    RESULT_GUARD_POSIX(s2n_stuffer_write_bytes(&bytes, before_ciphers, sizeof(before_ciphers)));

    size_t ciphers_size = cipher_count * S2N_TLS_CIPHER_SUITE_LEN;
    RESULT_GUARD_POSIX(s2n_stuffer_write_uint16(&bytes, ciphers_size));
    RESULT_GUARD_POSIX(s2n_stuffer_skip_write(&bytes, ciphers_size));

    uint8_t after_ciphers[] = {
        S2N_TEST_CLIENT_HELLO_AFTER_CIPHERS,
        S2N_TEST_CLIENT_HELLO_EMPTY_EXTENSIONS,
    };
    RESULT_GUARD_POSIX(s2n_stuffer_write_bytes(&bytes, after_ciphers, sizeof(after_ciphers)));
    RESULT_GUARD_POSIX(s2n_stuffer_write_vector_size(&message_size));

    size_t bytes_size = s2n_stuffer_data_available(&bytes);
    uint8_t *bytes_ptr = s2n_stuffer_raw_read(&bytes, bytes_size);
    RESULT_GUARD_PTR(bytes_ptr);

    DEFER_CLEANUP(struct s2n_client_hello *client_hello = NULL, s2n_client_hello_free);
    client_hello = s2n_client_hello_parse_message(bytes_ptr, bytes_size);
    RESULT_GUARD_PTR(client_hello);

    DEFER_CLEANUP(struct s2n_fingerprint *fingerprint = NULL, s2n_fingerprint_free);
    fingerprint = s2n_fingerprint_new(S2N_FINGERPRINT_JA4);
    RESULT_GUARD_PTR(fingerprint);
    RESULT_GUARD_POSIX(s2n_fingerprint_set_client_hello(fingerprint, client_hello));

    RESULT_GUARD_POSIX(s2n_fingerprint_get_hash(fingerprint,
            max_hash_size, hash, hash_size));
    return S2N_RESULT_OK;
}

static S2N_RESULT s2n_test_ja4_hash_from_extension_count(uint16_t extension_count,
        size_t max_hash_size, uint8_t *hash, uint32_t *hash_size)
{
    DEFER_CLEANUP(struct s2n_stuffer bytes = { 0 }, s2n_stuffer_free);
    RESULT_GUARD_POSIX(s2n_stuffer_growable_alloc(&bytes, 100));

    struct s2n_stuffer_reservation message_size = { 0 };
    RESULT_GUARD_POSIX(s2n_stuffer_write_uint8(&bytes, TLS_CLIENT_HELLO));
    RESULT_GUARD_POSIX(s2n_stuffer_reserve_uint24(&bytes, &message_size));

    uint8_t before_ciphers[] = {
        S2N_TEST_CLIENT_HELLO_VERSION,
        S2N_TEST_CLIENT_HELLO_AFTER_VERSION,
        S2N_TEST_CLIENT_HELLO_CIPHERS,
        S2N_TEST_CLIENT_HELLO_AFTER_CIPHERS,
    };
    RESULT_GUARD_POSIX(s2n_stuffer_write_bytes(&bytes, before_ciphers, sizeof(before_ciphers)));

    size_t extensions_size = extension_count * 4;
    RESULT_GUARD_POSIX(s2n_stuffer_write_uint16(&bytes, extensions_size));
    for (size_t i = 0; i < extension_count; i++) {
        RESULT_GUARD_POSIX(s2n_stuffer_write_uint16(&bytes, UINT16_MAX - i));
        RESULT_GUARD_POSIX(s2n_stuffer_write_uint16(&bytes, 0));
    }

    RESULT_GUARD_POSIX(s2n_stuffer_write_vector_size(&message_size));

    size_t bytes_size = s2n_stuffer_data_available(&bytes);
    uint8_t *bytes_ptr = s2n_stuffer_raw_read(&bytes, bytes_size);
    RESULT_GUARD_PTR(bytes_ptr);

    DEFER_CLEANUP(struct s2n_client_hello *client_hello = NULL, s2n_client_hello_free);
    client_hello = s2n_client_hello_parse_message(bytes_ptr, bytes_size);
    RESULT_GUARD_PTR(client_hello);

    DEFER_CLEANUP(struct s2n_fingerprint *fingerprint = NULL, s2n_fingerprint_free);
    fingerprint = s2n_fingerprint_new(S2N_FINGERPRINT_JA4);
    RESULT_GUARD_PTR(fingerprint);
    RESULT_GUARD_POSIX(s2n_fingerprint_set_client_hello(fingerprint, client_hello));

    RESULT_GUARD_POSIX(s2n_fingerprint_get_hash(fingerprint,
            max_hash_size, hash, hash_size));
    return S2N_RESULT_OK;
}

int main(int argc, char **argv)
{
    BEGIN_TEST();

    S2N_INIT_CLIENT_HELLO(minimal_client_hello_bytes,
            S2N_TEST_CLIENT_HELLO_VERSION,
            S2N_TEST_CLIENT_HELLO_AFTER_VERSION,
            S2N_TEST_CLIENT_HELLO_CIPHERS,
            S2N_TEST_CLIENT_HELLO_AFTER_CIPHERS,
            S2N_TEST_CLIENT_HELLO_EMPTY_EXTENSIONS);
    DEFER_CLEANUP(struct s2n_client_hello *minimal_client_hello = NULL, s2n_client_hello_free);
    minimal_client_hello = s2n_client_hello_parse_message(
            minimal_client_hello_bytes, sizeof(minimal_client_hello_bytes));
    EXPECT_NOT_NULL(minimal_client_hello);

    /* Test JA4_a: prefix
     *
     * JA4_a is a plaintext prefix describing the ClientHello, so we can make
     * specific assertions about its contents.
     */
    {
        /* Test protocol
         *
         *= https://raw.githubusercontent.com/FoxIO-LLC/ja4/v0.18.2/technical_details/JA4.md#quic
         *= type=test
         *# If the protocol is QUIC then the first character of the fingerprint is “q”
         *# if not, it’s “t”.
         */
        {
            /* Test QUIC */
            {
                S2N_INIT_CLIENT_HELLO_WITH_EXTENSION(client_hello_bytes,
                        TLS_EXTENSION_QUIC_TRANSPORT_PARAMETERS);

                uint8_t output[S2N_TEST_OUTPUT_SIZE] = { 0 };
                uint32_t output_size = 0;
                EXPECT_OK(s2n_test_ja4_hash_from_bytes(
                        client_hello_bytes, sizeof(client_hello_bytes),
                        sizeof(output), output, &output_size));

                EXPECT_TRUE(output_size > S2N_JA4_A_PROTOCOL);
                EXPECT_EQUAL(output[S2N_JA4_A_PROTOCOL], 'q');
            };

            /* Test not QUIC */
            {
                uint8_t output[S2N_TEST_OUTPUT_SIZE] = { 0 };
                uint32_t output_size = 0;
                EXPECT_OK(s2n_test_ja4_hash_from_bytes(
                        minimal_client_hello_bytes, sizeof(minimal_client_hello_bytes),
                        sizeof(output), output, &output_size));

                EXPECT_TRUE(output_size > S2N_JA4_A_PROTOCOL);
                EXPECT_EQUAL(output[S2N_JA4_A_PROTOCOL], 't');
            };
        };

        /* Test destination
         *
         *= https://raw.githubusercontent.com/FoxIO-LLC/ja4/v0.18.2/technical_details/JA4.md#sni
         *= type=test
         *# If the SNI extension (0x0000) exists, then the destination of the connection
         *# is a domain, or “d” in the fingerprint.
         *# If the SNI does not exist, then the destination is an IP address, or “i”.
         */
        {
            /* Test with SNI */
            {
                S2N_INIT_CLIENT_HELLO_WITH_EXTENSION(client_hello_bytes,
                        TLS_EXTENSION_SERVER_NAME);

                uint8_t output[S2N_TEST_OUTPUT_SIZE] = { 0 };
                uint32_t output_size = 0;
                EXPECT_OK(s2n_test_ja4_hash_from_bytes(
                        client_hello_bytes, sizeof(client_hello_bytes),
                        sizeof(output), output, &output_size));

                EXPECT_TRUE(output_size > S2N_JA4_A_DEST);
                EXPECT_EQUAL(output[S2N_JA4_A_DEST], 'd');
            };

            /* Test without SNI */
            {
                uint8_t output[S2N_TEST_OUTPUT_SIZE] = { 0 };
                uint32_t output_size = 0;
                EXPECT_OK(s2n_test_ja4_hash_from_bytes(
                        minimal_client_hello_bytes, sizeof(minimal_client_hello_bytes),
                        sizeof(output), output, &output_size));

                EXPECT_TRUE(output_size > S2N_JA4_A_DEST);
                EXPECT_EQUAL(output[S2N_JA4_A_DEST], 'i');
            };
        };

        /* Test version */
        {
            struct {
                uint8_t bytes[2];
                uint8_t version;
                const char *str;
            } test_cases[] = {
                /**
                 *= https://raw.githubusercontent.com/FoxIO-LLC/ja4/v0.18.2/technical_details/JA4.md#tls-version
                 *= type=test
                 *# 0x0304 = TLS 1.3 = “13”
                 *# 0x0303 = TLS 1.2 = “12”
                 *# 0x0302 = TLS 1.1 = “11”
                 *# 0x0301 = TLS 1.0 = “10”
                 */
                { .bytes = { 0x03, 0x04 }, .version = S2N_TLS13, .str = "13" },
                { .bytes = { 0x03, 0x03 }, .version = S2N_TLS12, .str = "12" },
                { .bytes = { 0x03, 0x02 }, .version = S2N_TLS11, .str = "11" },
                { .bytes = { 0x03, 0x01 }, .version = S2N_TLS10, .str = "10" },
                /**
                 *= https://raw.githubusercontent.com/FoxIO-LLC/ja4/v0.18.2/technical_details/JA4.md#tls-version
                 *= type=test
                 *# 0x0300 = SSL 3.0 = “s3”
                 *# 0x0200 = SSL 2.0 = “s2”
                 *# 0x0100 = SSL 1.0 = “s1”
                 */
                { .bytes = { 0x03, 0x00 }, .version = S2N_SSLv3, .str = "s3" },
                { .bytes = { 0x02, 0x00 }, .version = S2N_SSLv2, .str = "s2" },
                { .bytes = { 0x01, 0x00 }, .version = 10, .str = "s1" },
                /* Bad values */
                { .bytes = { 0x00, 0x00 }, .version = 0, .str = "00" },
                { .bytes = { 0x00, 0xFF }, .version = UINT8_MAX, .str = "00" },
                { .bytes = { 0xFF, 0xFF }, .version = UINT8_MAX, .str = "00" },
            };

            for (size_t i = 0; i < s2n_array_len(test_cases); i++) {
                /* Test record version not used.
                 *
                 *= https://raw.githubusercontent.com/FoxIO-LLC/ja4/v0.18.2/technical_details/JA4.md#tls-version
                 *= type=test
                 *# Handshake version (located at the top of the packet) should be ignored.
                 */
                if (strcmp(test_cases[i].str, "00") != 0) {
                    struct s2n_client_hello client_hello = *minimal_client_hello;
                    client_hello.legacy_version = 0;
                    client_hello.legacy_record_version = test_cases[i].version;

                    DEFER_CLEANUP(struct s2n_fingerprint *fingerprint = NULL,
                            s2n_fingerprint_free);
                    fingerprint = s2n_fingerprint_new(S2N_FINGERPRINT_JA4);
                    EXPECT_NOT_NULL(fingerprint);
                    EXPECT_SUCCESS(s2n_fingerprint_set_client_hello(fingerprint,
                            &client_hello));

                    uint8_t output[S2N_TEST_OUTPUT_SIZE] = { 0 };
                    uint32_t output_size = 0;
                    EXPECT_SUCCESS(s2n_fingerprint_get_hash(fingerprint,
                            sizeof(output), output, &output_size));

                    EXPECT_TRUE(output_size > S2N_JA4_A_VERSION_2);
                    EXPECT_FALSE((output[S2N_JA4_A_VERSION_1] == test_cases[i].str[0])
                            && (output[S2N_JA4_A_VERSION_2] == test_cases[i].str[1]));
                };

                /* Test version from extension
                 *
                 *= https://raw.githubusercontent.com/FoxIO-LLC/ja4/v0.18.2/technical_details/JA4.md#tls-version
                 *= type=test
                 *# If extension 0x002b exists (supported_versions), then the version
                 *# is the highest value in the extension.
                 */
                {
                    S2N_INIT_CLIENT_HELLO(client_hello_bytes,
                            S2N_TEST_CLIENT_HELLO_VERSION,
                            S2N_TEST_CLIENT_HELLO_AFTER_VERSION,
                            S2N_TEST_CLIENT_HELLO_CIPHERS,
                            S2N_TEST_CLIENT_HELLO_AFTER_CIPHERS,
                            /* extensions size */
                            0x00, 7,
                            /* extensions: supported versions */
                            0x00, TLS_EXTENSION_SUPPORTED_VERSIONS, 0x00, 3,
                            0x02, test_cases[i].bytes[0], test_cases[i].bytes[1]);

                    uint8_t output[S2N_TEST_OUTPUT_SIZE] = { 0 };
                    uint32_t output_size = 0;
                    EXPECT_OK(s2n_test_ja4_hash_from_bytes(
                            client_hello_bytes, sizeof(client_hello_bytes),
                            sizeof(output), output, &output_size));

                    EXPECT_TRUE(output_size > S2N_JA4_A_VERSION_2);
                    EXPECT_EQUAL(output[S2N_JA4_A_VERSION_1], test_cases[i].str[0]);
                    EXPECT_EQUAL(output[S2N_JA4_A_VERSION_2], test_cases[i].str[1]);
                };

                /* Test version from legacy field
                 *
                 *= https://raw.githubusercontent.com/FoxIO-LLC/ja4/v0.18.2/technical_details/JA4.md#tls-version
                 *= type=test
                 *# If the extension doesn’t exist, then the TLS version is the value
                 *# of the Protocol Version.
                 */
                {
                    S2N_INIT_CLIENT_HELLO(client_hello_bytes,
                            /* protocol version */
                            test_cases[i].bytes[0], test_cases[i].bytes[1],
                            S2N_TEST_CLIENT_HELLO_AFTER_VERSION,
                            S2N_TEST_CLIENT_HELLO_CIPHERS,
                            S2N_TEST_CLIENT_HELLO_AFTER_CIPHERS,
                            S2N_TEST_CLIENT_HELLO_EMPTY_EXTENSIONS);

                    uint8_t output[S2N_TEST_OUTPUT_SIZE] = { 0 };
                    uint32_t output_size = 0;
                    EXPECT_OK(s2n_test_ja4_hash_from_bytes(
                            client_hello_bytes, sizeof(client_hello_bytes),
                            sizeof(output), output, &output_size));

                    EXPECT_TRUE(output_size > S2N_JA4_A_VERSION_2);
                    EXPECT_EQUAL(output[S2N_JA4_A_VERSION_1], test_cases[i].str[0]);
                    EXPECT_EQUAL(output[S2N_JA4_A_VERSION_2], test_cases[i].str[1]);
                };
            }

            /* Test with grease values
             *
             *= https://raw.githubusercontent.com/FoxIO-LLC/ja4/v0.18.2/technical_details/JA4.md#tls-version
             *= type=test
             *# Remember to ignore GREASE values.
             */
            {
                S2N_INIT_CLIENT_HELLO(client_hello_bytes,
                        S2N_TEST_CLIENT_HELLO_VERSION,
                        S2N_TEST_CLIENT_HELLO_AFTER_VERSION,
                        S2N_TEST_CLIENT_HELLO_CIPHERS,
                        S2N_TEST_CLIENT_HELLO_AFTER_CIPHERS,
                        /* extensions size */
                        0x00, 13,
                        /* extensions: supported versions */
                        0x00, TLS_EXTENSION_SUPPORTED_VERSIONS, 0x00, 9,
                        /* supported version size */
                        8,
                        /* grease values */
                        0x0A, 0x0A,
                        0xAA, 0xAA,
                        0xFA, 0xFA,
                        /* actual value - lower than grease values */
                        test_cases[0].bytes[0], test_cases[0].bytes[1]);

                /* assert that test case is less than grease values */
                EXPECT_TRUE(test_cases[0].bytes[0] < 0x0A);

                uint8_t output[S2N_TEST_OUTPUT_SIZE] = { 0 };
                uint32_t output_size = 0;
                EXPECT_OK(s2n_test_ja4_hash_from_bytes(
                        client_hello_bytes, sizeof(client_hello_bytes),
                        sizeof(output), output, &output_size));

                EXPECT_TRUE(output_size > S2N_JA4_A_VERSION_2);
                EXPECT_EQUAL(output[S2N_JA4_A_VERSION_1], test_cases[0].str[0]);
                EXPECT_EQUAL(output[S2N_JA4_A_VERSION_2], test_cases[0].str[1]);
            };
        };

        const struct {
            uint8_t size;
            const char *str;
        } count_test_cases[] = {
            /**
             *= https://raw.githubusercontent.com/FoxIO-LLC/ja4/v0.18.2/technical_details/JA4.md#number-of-ciphers
             *= type=test
             *# if there’s 6 cipher suites in the hello packet, then the
             *# value should be “06”.
             */
            { .size = 6, .str = "06" },
            { .size = 12, .str = "12" },
            { .size = 50, .str = "50" },
            { .size = 99, .str = "99" },
            /**
             *= https://raw.githubusercontent.com/FoxIO-LLC/ja4/v0.18.2/technical_details/JA4.md#number-of-ciphers
             *= type=test
             *# If there’s > 99, which there should never be, then output “99”.
             */
            { .size = 100, .str = "99" },
            { .size = 255, .str = "99" },
        };

        /* Test number of cipher suites */
        {
            /* Test basic cipher suite list
             *
             *= https://raw.githubusercontent.com/FoxIO-LLC/ja4/v0.18.2/technical_details/JA4.md#number-of-ciphers
             *= type=test
             *# 2 character number of cipher suites, so if there’s 6 cipher suites
             *# in the hello packet, then the value should be “06”.
             */
            for (size_t i = 0; i < s2n_array_len(count_test_cases); i++) {
                uint8_t output[S2N_TEST_OUTPUT_SIZE] = { 0 };
                uint32_t output_size = 0;
                EXPECT_OK(s2n_test_ja4_hash_from_cipher_count(count_test_cases[i].size,
                        sizeof(output), output, &output_size));

                EXPECT_TRUE(output_size > S2N_JA4_A_CIPHER_COUNT_2);
                EXPECT_EQUAL(output[S2N_JA4_A_CIPHER_COUNT_1], count_test_cases[i].str[0]);
                EXPECT_EQUAL(output[S2N_JA4_A_CIPHER_COUNT_2], count_test_cases[i].str[1]);
            };

            /* Test with grease values
             *
             *= https://raw.githubusercontent.com/FoxIO-LLC/ja4/v0.18.2/technical_details/JA4.md#number-of-ciphers
             *= type=test
             *# Remember, ignore GREASE values. They don’t count.
             */
            {
                S2N_INIT_CLIENT_HELLO(client_hello_bytes,
                        S2N_TEST_CLIENT_HELLO_VERSION,
                        S2N_TEST_CLIENT_HELLO_AFTER_VERSION,
                        /* cipher suites size */
                        0x00, 8,
                        /* ciphers suites */
                        /* grease values */
                        0x0A, 0x0A,
                        0xAA, 0xAA,
                        0xFA, 0xFA,
                        /* non-grease value */
                        0x00, 0x00,
                        S2N_TEST_CLIENT_HELLO_AFTER_CIPHERS,
                        S2N_TEST_CLIENT_HELLO_EMPTY_EXTENSIONS);

                uint8_t output[S2N_TEST_OUTPUT_SIZE] = { 0 };
                uint32_t output_size = 0;
                EXPECT_OK(s2n_test_ja4_hash_from_bytes(
                        client_hello_bytes, sizeof(client_hello_bytes),
                        sizeof(output), output, &output_size));

                EXPECT_TRUE(output_size > S2N_JA4_A_CIPHER_COUNT_2);
                EXPECT_EQUAL(output[S2N_JA4_A_CIPHER_COUNT_1], '0');
                EXPECT_EQUAL(output[S2N_JA4_A_CIPHER_COUNT_2], '1');
            };
        };

        /* Test number of extensions
         *
         *= https://raw.githubusercontent.com/FoxIO-LLC/ja4/v0.18.2/technical_details/JA4.md#number-of-extensions
         *= type=test
         *# Same as counting ciphers.
         */
        {
            /* Test basic extension list */
            for (size_t i = 0; i < s2n_array_len(count_test_cases); i++) {
                uint8_t output[S2N_TEST_OUTPUT_SIZE] = { 0 };
                uint32_t output_size = 0;
                EXPECT_OK(s2n_test_ja4_hash_from_extension_count(count_test_cases[i].size,
                        sizeof(output), output, &output_size));

                EXPECT_TRUE(output_size > S2N_JA4_A_EXT_COUNT_2);
                EXPECT_EQUAL(output[S2N_JA4_A_EXT_COUNT_1], count_test_cases[i].str[0]);
                EXPECT_EQUAL(output[S2N_JA4_A_EXT_COUNT_2], count_test_cases[i].str[1]);
            };

            /* Test with grease values
             *
             *= https://raw.githubusercontent.com/FoxIO-LLC/ja4/v0.18.2/technical_details/JA4.md#number-of-extensions
             *= type=test
             *# Ignore GREASE.
             */
            {
                S2N_INIT_CLIENT_HELLO(client_hello_bytes,
                        S2N_TEST_CLIENT_HELLO_VERSION,
                        S2N_TEST_CLIENT_HELLO_AFTER_VERSION,
                        S2N_TEST_CLIENT_HELLO_CIPHERS,
                        S2N_TEST_CLIENT_HELLO_AFTER_CIPHERS,
                        /* extensions size */
                        0x00, 16,
                        /* extensions */
                        /* grease values */
                        0x0A, 0x0A, S2N_TEST_CLIENT_HELLO_EMPTY_EXTENSION,
                        0xAA, 0xAA, S2N_TEST_CLIENT_HELLO_EMPTY_EXTENSION,
                        0xFA, 0xFA, S2N_TEST_CLIENT_HELLO_EMPTY_EXTENSION,
                        /* non-grease values */
                        0x00, 0x00, S2N_TEST_CLIENT_HELLO_EMPTY_EXTENSION);

                uint8_t output[S2N_TEST_OUTPUT_SIZE] = { 0 };
                uint32_t output_size = 0;
                EXPECT_OK(s2n_test_ja4_hash_from_bytes(
                        client_hello_bytes, sizeof(client_hello_bytes),
                        sizeof(output), output, &output_size));

                EXPECT_TRUE(output_size > S2N_JA4_A_EXT_COUNT_2);
                EXPECT_EQUAL(output[S2N_JA4_A_EXT_COUNT_1], '0');
                EXPECT_EQUAL(output[S2N_JA4_A_EXT_COUNT_2], '1');
            };

            /* Ensure SNI and ALPN are included
             *
             *= https://raw.githubusercontent.com/FoxIO-LLC/ja4/v0.18.2/technical_details/JA4.md#number-of-extensions
             *= type=test
             *# Include SNI and ALPN.
             */
            {
                S2N_INIT_CLIENT_HELLO(client_hello_bytes,
                        S2N_TEST_CLIENT_HELLO_VERSION,
                        S2N_TEST_CLIENT_HELLO_AFTER_VERSION,
                        S2N_TEST_CLIENT_HELLO_CIPHERS,
                        S2N_TEST_CLIENT_HELLO_AFTER_CIPHERS,
                        /* extensions size */
                        0x00, 8,
                        /* extensions */
                        0x00, TLS_EXTENSION_SERVER_NAME, S2N_TEST_CLIENT_HELLO_EMPTY_EXTENSION,
                        0x00, TLS_EXTENSION_ALPN, S2N_TEST_CLIENT_HELLO_EMPTY_EXTENSION);

                uint8_t output[S2N_TEST_OUTPUT_SIZE] = { 0 };
                uint32_t output_size = 0;
                EXPECT_OK(s2n_test_ja4_hash_from_bytes(
                        client_hello_bytes, sizeof(client_hello_bytes),
                        sizeof(output), output, &output_size));

                EXPECT_TRUE(output_size > S2N_JA4_A_EXT_COUNT_2);
                EXPECT_EQUAL(output[S2N_JA4_A_EXT_COUNT_1], '0');
                EXPECT_EQUAL(output[S2N_JA4_A_EXT_COUNT_2], '2');
            };
        };

        /* Test ALPN */
        {
            /* Test basic ALPN
             *
             *= https://raw.githubusercontent.com/FoxIO-LLC/ja4/v0.18.2/technical_details/JA4.md#alpn-extension-value
             *= type=test
             *# The first and last characters of the ALPN (Application-Layer
             *# Protocol Negotiation) first value.
             */
            {
                /* 2 characters: h2
                 *
                 *= https://raw.githubusercontent.com/FoxIO-LLC/ja4/v0.18.2/technical_details/JA4.md#alpn-extension-value
                 *= type=test
                 *# In the above example, the first ALPN value is h2 so the first
                 *# and last characters to use in the fingerprint are “h2”.
                 */
                {
                    S2N_INIT_CLIENT_HELLO(client_hello_bytes,
                            S2N_TEST_CLIENT_HELLO_VERSION,
                            S2N_TEST_CLIENT_HELLO_AFTER_VERSION,
                            S2N_TEST_CLIENT_HELLO_CIPHERS,
                            S2N_TEST_CLIENT_HELLO_AFTER_CIPHERS,
                            /* extensions size */
                            0x00, 16,
                            /* extension: alpn */
                            0x00, TLS_EXTENSION_ALPN, 0x00, 12,
                            0x00, 10,
                            0, 0x00, 2, 'h', '2',
                            0, 0x00, 2, 'h', '3');

                    uint8_t output[S2N_TEST_OUTPUT_SIZE] = { 0 };
                    uint32_t output_size = 0;
                    EXPECT_OK(s2n_test_ja4_hash_from_bytes(
                            client_hello_bytes, sizeof(client_hello_bytes),
                            sizeof(output), output, &output_size));

                    EXPECT_TRUE(output_size > S2N_JA4_A_ALPN_LAST);
                    EXPECT_EQUAL(output[S2N_JA4_A_ALPN_FIRST], 'h');
                    EXPECT_EQUAL(output[S2N_JA4_A_ALPN_LAST], '2');
                };

                /* More than 2 characters: "http/1.1"
                 *
                 *= https://raw.githubusercontent.com/FoxIO-LLC/ja4/v0.18.2/technical_details/JA4.md#alpn-extension-value
                 *= type=test
                 *# IF the first ALPN listed was http/1.1 then the first and last
                 *# characters to use in the fingerprint would be “h1”.
                 */
                {
                    S2N_INIT_CLIENT_HELLO(client_hello_bytes,
                            S2N_TEST_CLIENT_HELLO_VERSION,
                            S2N_TEST_CLIENT_HELLO_AFTER_VERSION,
                            S2N_TEST_CLIENT_HELLO_CIPHERS,
                            S2N_TEST_CLIENT_HELLO_AFTER_CIPHERS,
                            /* extensions size */
                            0x00, 24,
                            /* extension: alpn */
                            0x00, TLS_EXTENSION_ALPN, 0x00, 20,
                            0x00, 18,
                            0, 0x00, 8, 'h', 't', 't', 'p', '/', '1', '.', '1',
                            0, 0x00, 4, 'q', 'u', 'i', 'c');

                    uint8_t output[S2N_TEST_OUTPUT_SIZE] = { 0 };
                    uint32_t output_size = 0;
                    EXPECT_OK(s2n_test_ja4_hash_from_bytes(
                            client_hello_bytes, sizeof(client_hello_bytes),
                            sizeof(output), output, &output_size));

                    EXPECT_TRUE(output_size > S2N_JA4_A_ALPN_LAST);
                    EXPECT_EQUAL(output[S2N_JA4_A_ALPN_FIRST], 'h');
                    EXPECT_EQUAL(output[S2N_JA4_A_ALPN_LAST], '1');
                };
            };

            /* Test 1-byte alpn value */
            {
                S2N_INIT_CLIENT_HELLO(client_hello_bytes,
                        S2N_TEST_CLIENT_HELLO_VERSION,
                        S2N_TEST_CLIENT_HELLO_AFTER_VERSION,
                        S2N_TEST_CLIENT_HELLO_CIPHERS,
                        S2N_TEST_CLIENT_HELLO_AFTER_CIPHERS,
                        /* extensions size */
                        0x00, 10,
                        /* extension: alpn */
                        0x00, TLS_EXTENSION_ALPN, 0x00, 6,
                        0x00, 4,
                        0, 0x00, 1, 'q');

                uint8_t output[S2N_TEST_OUTPUT_SIZE] = { 0 };
                uint32_t output_size = 0;
                EXPECT_OK(s2n_test_ja4_hash_from_bytes(
                        client_hello_bytes, sizeof(client_hello_bytes),
                        sizeof(output), output, &output_size));

                EXPECT_TRUE(output_size > S2N_JA4_A_ALPN_LAST);
                EXPECT_EQUAL(output[S2N_JA4_A_ALPN_FIRST], 'q');
                EXPECT_EQUAL(output[S2N_JA4_A_ALPN_LAST], '0');
            };

            /* Test non-ascii alpn value */
            {
                S2N_INIT_CLIENT_HELLO(client_hello_bytes,
                        S2N_TEST_CLIENT_HELLO_VERSION,
                        S2N_TEST_CLIENT_HELLO_AFTER_VERSION,
                        S2N_TEST_CLIENT_HELLO_CIPHERS,
                        S2N_TEST_CLIENT_HELLO_AFTER_CIPHERS,
                        /* extensions size */
                        0x00, 11,
                        /* extension: alpn */
                        0x00, TLS_EXTENSION_ALPN, 0x00, 7,
                        0x00, 5,
                        0, 0x00, 2, UINT8_MAX, 128);

                uint8_t output[S2N_TEST_OUTPUT_SIZE] = { 0 };
                uint32_t output_size = 0;
                EXPECT_OK(s2n_test_ja4_hash_from_bytes(
                        client_hello_bytes, sizeof(client_hello_bytes),
                        sizeof(output), output, &output_size));

                EXPECT_TRUE(output_size > S2N_JA4_A_ALPN_LAST);
                EXPECT_EQUAL(output[S2N_JA4_A_ALPN_FIRST], '9');
                EXPECT_EQUAL(output[S2N_JA4_A_ALPN_LAST], '9');
            };

            /* Test no ALPN
             *
             *= https://raw.githubusercontent.com/FoxIO-LLC/ja4/v0.18.2/technical_details/JA4.md#alpn-extension-value
             *= type=test
             *# If there are no ALPN values or no ALPN extension then we print
             *# “00” as the value in the fingerprint.
             */
            {
                /* Test no ALPN extension */
                {
                    uint8_t output[S2N_TEST_OUTPUT_SIZE] = { 0 };
                    uint32_t output_size = 0;
                    EXPECT_OK(s2n_test_ja4_hash_from_bytes(
                            minimal_client_hello_bytes, sizeof(minimal_client_hello_bytes),
                            sizeof(output), output, &output_size));

                    EXPECT_TRUE(output_size > S2N_JA4_A_ALPN_LAST);
                    EXPECT_EQUAL(output[S2N_JA4_A_ALPN_FIRST], '0');
                    EXPECT_EQUAL(output[S2N_JA4_A_ALPN_LAST], '0');
                };

                /* Test no ALPN values */
                {
                    S2N_INIT_CLIENT_HELLO(client_hello_bytes,
                            S2N_TEST_CLIENT_HELLO_VERSION,
                            S2N_TEST_CLIENT_HELLO_AFTER_VERSION,
                            S2N_TEST_CLIENT_HELLO_CIPHERS,
                            S2N_TEST_CLIENT_HELLO_AFTER_CIPHERS,
                            /* extensions size */
                            0x00, 6,
                            /* extension: alpn */
                            0x00, TLS_EXTENSION_ALPN, 0x00, 2,
                            0x00, 0);

                    uint8_t output[S2N_TEST_OUTPUT_SIZE] = { 0 };
                    uint32_t output_size = 0;
                    EXPECT_OK(s2n_test_ja4_hash_from_bytes(
                            client_hello_bytes, sizeof(client_hello_bytes),
                            sizeof(output), output, &output_size));

                    EXPECT_TRUE(output_size > S2N_JA4_A_ALPN_LAST);
                    EXPECT_EQUAL(output[S2N_JA4_A_ALPN_FIRST], '0');
                    EXPECT_EQUAL(output[S2N_JA4_A_ALPN_LAST], '0');
                };

                /* Test empty / invalid alpn value */
                {
                    S2N_INIT_CLIENT_HELLO(client_hello_bytes,
                            S2N_TEST_CLIENT_HELLO_VERSION,
                            S2N_TEST_CLIENT_HELLO_AFTER_VERSION,
                            S2N_TEST_CLIENT_HELLO_CIPHERS,
                            S2N_TEST_CLIENT_HELLO_AFTER_CIPHERS,
                            /* extensions size */
                            0x00, 9,
                            /* extension: alpn */
                            0x00, TLS_EXTENSION_ALPN, 0x00, 5,
                            0x00, 3,
                            0, 0x00, 0);

                    uint8_t output[S2N_TEST_OUTPUT_SIZE] = { 0 };
                    uint32_t output_size = 0;
                    EXPECT_OK(s2n_test_ja4_hash_from_bytes(
                            client_hello_bytes, sizeof(client_hello_bytes),
                            sizeof(output), output, &output_size));

                    EXPECT_TRUE(output_size > S2N_JA4_A_ALPN_LAST);
                    EXPECT_EQUAL(output[S2N_JA4_A_ALPN_FIRST], '0');
                    EXPECT_EQUAL(output[S2N_JA4_A_ALPN_LAST], '0');
                };
            };
        };
    };

    /* Test JA4_b: cipher suites */
    {
        /* clang-format off */
        S2N_INIT_CLIENT_HELLO(client_hello_bytes,
            S2N_TEST_CLIENT_HELLO_VERSION,
            S2N_TEST_CLIENT_HELLO_AFTER_VERSION,
            /* cipher suites size */
            0x00, 30,
            /* cipher suites
             *
             *= https://raw.githubusercontent.com/FoxIO-LLC/ja4/v0.18.2/technical_details/JA4.md#cipher-hash
             *= type=test
             *# Example:
             *# ```
             *# 1301,1302,1303,c02b,c02f,
             */
            0x13, 0x01, 0x13, 0x02, 0x13, 0x03, 0xc0, 0x2b, 0xc0, 0x2f,
            /*
             *= https://raw.githubusercontent.com/FoxIO-LLC/ja4/v0.18.2/technical_details/JA4.md#cipher-hash
             *= type=test
             *# c02c,c030,cca9,cca8,c013,
             */
            0xc0, 0x2c, 0xc0, 0x30, 0xcc, 0xa9, 0xcc, 0xa8, 0xc0, 0x13,
            /*
             *= https://raw.githubusercontent.com/FoxIO-LLC/ja4/v0.18.2/technical_details/JA4.md#cipher-hash
             *= type=test
             *# c014,009c,009d,002f,0035
             *# ```
             */
            0xc0, 0x14, 0x00, 0x9c, 0x00, 0x9d, 0x00, 0x2f, 0x00, 0x35,
            S2N_TEST_CLIENT_HELLO_AFTER_CIPHERS,
            S2N_TEST_CLIENT_HELLO_EMPTY_EXTENSIONS,
        );
        /* clang-format on */

        /* Test raw list
         *
         *= https://raw.githubusercontent.com/FoxIO-LLC/ja4/v0.18.2/technical_details/JA4.md#cipher-hash
         *= type=test
         *# The list is created using the 4 character hex values of the ciphers,
         *# lower case, comma delimited, ignoring GREASE.
         */
        {
            /* Expected result from docs
             *
             *= https://raw.githubusercontent.com/FoxIO-LLC/ja4/v0.18.2/technical_details/JA4.md#cipher-hash
             *= type=test
             *# 002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9
             */
            const char expected[] =
                    "002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9";

            uint8_t output[S2N_TEST_OUTPUT_SIZE] = { 0 };
            uint32_t output_size = 0;
            EXPECT_OK(s2n_test_ja4_raw_from_bytes(
                    client_hello_bytes, sizeof(client_hello_bytes),
                    sizeof(output), output, &output_size));

            EXPECT_TRUE(output_size > S2N_JA4_B_START);
            uint8_t *output_b = &output[S2N_JA4_B_START];
            EXPECT_TRUE(output_size >= S2N_JA4_B_START + strlen(expected));
            EXPECT_BYTEARRAY_EQUAL(output_b, expected, strlen(expected));
        };

        /* Test hashed list
         *
         *= https://raw.githubusercontent.com/FoxIO-LLC/ja4/v0.18.2/technical_details/JA4.md#cipher-hash
         *= type=test
         *# A 12 character truncated sha256 hash of the list of ciphers sorted
         *# in hex order, first 12 characters.
         */
        {
            /* Expected result from docs
             *
             *= https://raw.githubusercontent.com/FoxIO-LLC/ja4/v0.18.2/technical_details/JA4.md#cipher-hash
             *= type=test
             *# = 8daaf6152771
             */
            const char expected[] = "8daaf6152771";

            uint8_t output[S2N_TEST_OUTPUT_SIZE] = { 0 };
            uint32_t output_size = 0;
            EXPECT_OK(s2n_test_ja4_hash_from_bytes(
                    client_hello_bytes, sizeof(client_hello_bytes),
                    sizeof(output), output, &output_size));

            EXPECT_TRUE(output_size > S2N_JA4_B_START);
            uint8_t *output_b = &output[S2N_JA4_B_START];
            EXPECT_TRUE(output_size >= S2N_JA4_B_START + strlen(expected));
            EXPECT_BYTEARRAY_EQUAL(output_b, expected, strlen(expected));
        };

        /* Test sorting
         *
         *= https://raw.githubusercontent.com/FoxIO-LLC/ja4/v0.18.2/technical_details/JA4.md#cipher-hash
         *= type=test
         *# list of ciphers sorted in hex order
         */
        {
            const char expected[] =
                    "0001,0002,0003,"
                    "000a,000b,000c,"
                    "0100,0200,0300,"
                    "0a00,0b00,0c00";

            /* Already sorted */
            {
                S2N_INIT_CLIENT_HELLO(bytes,
                        S2N_TEST_CLIENT_HELLO_VERSION,
                        S2N_TEST_CLIENT_HELLO_AFTER_VERSION,
                        /* cipher suites size */
                        0x00, 24,
                        /* cipher suites in sorted order */
                        0x00, 0x01, 0x00, 0x02, 0x00, 0x03,
                        0x01, 0x00, 0x02, 0x00, 0x03, 0x00,
                        0x00, 0x0a, 0x00, 0x0b, 0x00, 0x0c,
                        0x0a, 0x00, 0x0b, 0x00, 0x0c, 0x00,
                        S2N_TEST_CLIENT_HELLO_AFTER_CIPHERS,
                        S2N_TEST_CLIENT_HELLO_EMPTY_EXTENSIONS);

                uint8_t output[S2N_TEST_OUTPUT_SIZE] = { 0 };
                uint32_t output_size = 0;
                EXPECT_OK(s2n_test_ja4_raw_from_bytes(bytes, sizeof(bytes),
                        sizeof(output), output, &output_size));

                EXPECT_TRUE(output_size > S2N_JA4_B_START);
                uint8_t *output_b = &output[S2N_JA4_B_START];
                EXPECT_TRUE(output_size >= S2N_JA4_B_START + strlen(expected));
                EXPECT_BYTEARRAY_EQUAL(output_b, expected, strlen(expected));
            };

            /* Reversed */
            {
                S2N_INIT_CLIENT_HELLO(bytes,
                        S2N_TEST_CLIENT_HELLO_VERSION,
                        S2N_TEST_CLIENT_HELLO_AFTER_VERSION,
                        /* cipher suites size */
                        0x00, 24,
                        /* cipher suites in reversed order */
                        0x0c, 0x00, 0x0b, 0x00, 0x0a, 0x00,
                        0x00, 0x0c, 0x00, 0x0b, 0x00, 0x0a,
                        0x03, 0x00, 0x02, 0x00, 0x01, 0x00,
                        0x00, 0x03, 0x00, 0x02, 0x00, 0x01,
                        S2N_TEST_CLIENT_HELLO_AFTER_CIPHERS,
                        S2N_TEST_CLIENT_HELLO_EMPTY_EXTENSIONS);

                uint8_t output[S2N_TEST_OUTPUT_SIZE] = { 0 };
                uint32_t output_size = 0;
                EXPECT_OK(s2n_test_ja4_raw_from_bytes(bytes, sizeof(bytes),
                        sizeof(output), output, &output_size));

                EXPECT_TRUE(output_size > S2N_JA4_B_START);
                uint8_t *output_b = &output[S2N_JA4_B_START];
                EXPECT_TRUE(output_size >= S2N_JA4_B_START + strlen(expected));
                EXPECT_BYTEARRAY_EQUAL(output_b, expected, strlen(expected));
            };

            /* Randomized */
            {
                S2N_INIT_CLIENT_HELLO(bytes,
                        S2N_TEST_CLIENT_HELLO_VERSION,
                        S2N_TEST_CLIENT_HELLO_AFTER_VERSION,
                        /* cipher suites size */
                        0x00, 24,
                        /* cipher suites in randomized order */
                        0x0a, 0x00, 0x00, 0x0b, 0x00, 0x03,
                        0x00, 0x01, 0x02, 0x00, 0x0b, 0x00,
                        0x01, 0x00, 0x00, 0x0a, 0x0c, 0x00,
                        0x00, 0x0c, 0x03, 0x00, 0x00, 0x02,
                        S2N_TEST_CLIENT_HELLO_AFTER_CIPHERS,
                        S2N_TEST_CLIENT_HELLO_EMPTY_EXTENSIONS);

                uint8_t output[S2N_TEST_OUTPUT_SIZE] = { 0 };
                uint32_t output_size = 0;
                EXPECT_OK(s2n_test_ja4_raw_from_bytes(bytes, sizeof(bytes),
                        sizeof(output), output, &output_size));

                EXPECT_TRUE(output_size > S2N_JA4_B_START);
                uint8_t *output_b = &output[S2N_JA4_B_START];
                EXPECT_TRUE(output_size >= S2N_JA4_B_START + strlen(expected));
                EXPECT_BYTEARRAY_EQUAL(output_b, expected, strlen(expected));
            };
        };
    };

    /* Test JA4_c: extensions and signature algorithms */
    {
        /* clang-format off */
        S2N_INIT_CLIENT_HELLO(client_hello_bytes,
            S2N_TEST_CLIENT_HELLO_VERSION,
            S2N_TEST_CLIENT_HELLO_AFTER_VERSION,
            S2N_TEST_CLIENT_HELLO_CIPHERS,
            S2N_TEST_CLIENT_HELLO_AFTER_CIPHERS,
            /* extensions size
             * There are 16 extensions (2 byte type + 2 bytes size),
             * and the signature algorithms contribute the remaining bytes. */
            0x00, (16 * 4) + (9 * 2),
            /* extensions
             *
             *= https://raw.githubusercontent.com/FoxIO-LLC/ja4/v0.18.2/technical_details/JA4.md#extension-hash
             *= type=test
             *# For example:
             *# ```
             *# 001b,0000,0033,0010,4469,0017,002d,000d,
             */
            0x00, 0x1b, S2N_TEST_CLIENT_HELLO_EMPTY_EXTENSION,
            0x00, 0x00, S2N_TEST_CLIENT_HELLO_EMPTY_EXTENSION,
            0x00, 0x33, S2N_TEST_CLIENT_HELLO_EMPTY_EXTENSION,
            0x00, 0x10, S2N_TEST_CLIENT_HELLO_EMPTY_EXTENSION,
            0x44, 0x69, S2N_TEST_CLIENT_HELLO_EMPTY_EXTENSION,
            0x00, 0x17, S2N_TEST_CLIENT_HELLO_EMPTY_EXTENSION,
            0x00, 0x2d, S2N_TEST_CLIENT_HELLO_EMPTY_EXTENSION,
            0x00, 0x0d, 0x00, 9 * 2,
            /* signature algorithms size */
            0x00, 8 * 2,
            /* signature algorithms
             *= https://raw.githubusercontent.com/FoxIO-LLC/ja4/v0.18.2/technical_details/JA4.md#extension-hash
             *= type=test
             *# For example the signature algorithms:
             *# ```
             *# 0403,0804,0401,0503,0805,0501,0806,0601
             *# ```
             */
            0x04, 0x03, 0x08, 0x04, 0x04, 0x01, 0x05, 0x03,
            0x08, 0x05, 0x05, 0x01, 0x08, 0x06, 0x06, 0x01,
            /* more extensions
             *
             *= https://raw.githubusercontent.com/FoxIO-LLC/ja4/v0.18.2/technical_details/JA4.md#extension-hash
             *= type=test
             *# 0005,0023,0012,002b,ff01,000b,000a,0015
             *# ```
             */
            0x00, 0x05, S2N_TEST_CLIENT_HELLO_EMPTY_EXTENSION,
            0x00, 0x23, S2N_TEST_CLIENT_HELLO_EMPTY_EXTENSION,
            0x00, 0x12, S2N_TEST_CLIENT_HELLO_EMPTY_EXTENSION,
            0x00, 0x2b, S2N_TEST_CLIENT_HELLO_EMPTY_EXTENSION,
            0xff, 0x01, S2N_TEST_CLIENT_HELLO_EMPTY_EXTENSION,
            0x00, 0x0b, S2N_TEST_CLIENT_HELLO_EMPTY_EXTENSION,
            0x00, 0x0a, S2N_TEST_CLIENT_HELLO_EMPTY_EXTENSION,
            0x00, 0x15, S2N_TEST_CLIENT_HELLO_EMPTY_EXTENSION,
        );
        /* clang-format on */

        /* Expected raw extensions string from docs
         *
         *= https://raw.githubusercontent.com/FoxIO-LLC/ja4/v0.18.2/technical_details/JA4.md#extension-hash
         *= type=test
         *# 0005,000a,000b,000d,0012,0015,0017,001b,0023,002b,002d,0033,4469,ff01
         */
        const char expected_raw_extensions[] =
                "0005,000a,000b,000d,0012,0015,0017,001b,0023,002b,002d,0033,4469,ff01";

        /* Test that SNI and ALPN are ignored
         *
         * Instead of actually testing this, we just test that the known value
         * will test that SNI and ALPN are ignored.
         *
         *= https://raw.githubusercontent.com/FoxIO-LLC/ja4/v0.18.2/technical_details/JA4.md#extension-hash
         *= type=test
         *# Ignore the SNI extension (0000) and the ALPN extension (0010)
         *# as we’ve already captured them in the _a_ section of the fingerprint.
         */
        {
            const char sni_str[] = "0000";
            const char alpn_str[] = "0010";

            /* Known value from docs, in string form
             *
             *= https://raw.githubusercontent.com/FoxIO-LLC/ja4/v0.18.2/technical_details/JA4.md#extension-hash
             *= type=test
             *# For example:
             *# ```
             *# 001b,0000,0033,0010,4469,0017,002d,000d,0005,0023,0012,002b,ff01,000b,000a,0015
             *# ```
             */
            const char extensions[] =
                    "001b,0000,0033,0010,4469,0017,002d,000d,0005,0023,0012,002b,ff01,000b,000a,0015";
            EXPECT_NOT_NULL(strstr(extensions, sni_str));
            EXPECT_NOT_NULL(strstr(extensions, alpn_str));

            /* Expected result from docs
             *
             *= https://raw.githubusercontent.com/FoxIO-LLC/ja4/v0.18.2/technical_details/JA4.md#extension-hash
             *= type=test
             *# 0005,000a,000b,000d,0012,0015,0017,001b,0023,002b,002d,0033,4469,ff01
             */
            EXPECT_NULL(strstr(expected_raw_extensions, sni_str));
            EXPECT_NULL(strstr(expected_raw_extensions, alpn_str));
        };

        /* Test raw extension list
         *
         *= https://raw.githubusercontent.com/FoxIO-LLC/ja4/v0.18.2/technical_details/JA4.md#extension-hash
         *= type=test
         *# The extension list is created using the 4 character hex values of the extensions,
         *# lower case, comma delimited, sorted (not in the order they appear).
         */
        {
            const char *expected = expected_raw_extensions;

            uint8_t output[S2N_TEST_OUTPUT_SIZE] = { 0 };
            uint32_t output_size = 0;
            EXPECT_OK(s2n_test_ja4_raw_from_bytes(
                    client_hello_bytes, sizeof(client_hello_bytes),
                    sizeof(output), output, &output_size));

            EXPECT_TRUE(output_size > S2N_JA4_C_RAW_START);
            uint8_t *output_c = &output[S2N_JA4_C_RAW_START];
            EXPECT_TRUE(output_size >= S2N_JA4_C_RAW_START + strlen(expected));
            EXPECT_BYTEARRAY_EQUAL(output_c, expected, strlen(expected));
        };

        /* Test raw signature algorithms list
         *
         *= https://raw.githubusercontent.com/FoxIO-LLC/ja4/v0.18.2/technical_details/JA4.md#extension-hash
         *= type=test
         *# The signature algorithm hex values are then added to the end of the
         *# list in the order that they appear (not sorted) with an underscore
         *# delimiting the two lists.
         */
        {
            /* Expected result from docs
             *
             *= https://raw.githubusercontent.com/FoxIO-LLC/ja4/v0.18.2/technical_details/JA4.md#extension-hash
             *= type=test
             *# Are added to the end of the previous string to create:
             *# ```
             *# 0005,000a,000b,000d,0012,0015,0017,001b,0023,002b,002d,0033,4469,ff01_0403,0804,0401,0503,0805,0501,0806,0601
             *# ```
             */
            const char expected[] =
                    "0005,000a,000b,000d,0012,0015,0017,001b,0023,002b,002d,"
                    "0033,4469,ff01_0403,0804,0401,0503,0805,0501,0806,0601";

            uint8_t output[S2N_TEST_OUTPUT_SIZE] = { 0 };
            uint32_t output_size = 0;
            EXPECT_OK(s2n_test_ja4_raw_from_bytes(
                    client_hello_bytes, sizeof(client_hello_bytes),
                    sizeof(output), output, &output_size));

            EXPECT_TRUE(output_size > S2N_JA4_C_RAW_START);
            uint8_t *output_c = &output[S2N_JA4_C_RAW_START];
            EXPECT_TRUE(output_size >= S2N_JA4_C_RAW_START + strlen(expected));
            EXPECT_BYTEARRAY_EQUAL(output_c, expected, strlen(expected));
        };

        /* Test hashed lists
         *
         *= https://raw.githubusercontent.com/FoxIO-LLC/ja4/v0.18.2/technical_details/JA4.md#extension-hash
         *= type=test
         *# A 12 character truncated sha256 hash of the list of extensions,
         *# sorted by hex value, followed by the list of signature algorithms,
         *# in the order that they appear (not sorted).
         */
        {
            /* Expected result from docs
             *
             *= https://raw.githubusercontent.com/FoxIO-LLC/ja4/v0.18.2/technical_details/JA4.md#extension-hash
             *= type=test
             *# Hashed to:
             *# ```
             *# e5627efa2ab19723084c1033a96c694a45826ab5a460d2d3fd5ffcfe97161c95
             *# ```
             *# Truncated to first 12 characters:
             *# ```
             *# e5627efa2ab1
             *# ```
             */
            const char expected[] = "e5627efa2ab1";

            uint8_t output[S2N_TEST_OUTPUT_SIZE] = { 0 };
            uint32_t output_size = 0;
            EXPECT_OK(s2n_test_ja4_hash_from_bytes(
                    client_hello_bytes, sizeof(client_hello_bytes),
                    sizeof(output), output, &output_size));

            EXPECT_TRUE(output_size > S2N_JA4_C_HASH_START);
            uint8_t *output_c = &output[S2N_JA4_C_HASH_START];
            EXPECT_TRUE(output_size >= S2N_JA4_C_HASH_START + strlen(expected));
            EXPECT_BYTEARRAY_EQUAL(output_c, expected, strlen(expected));
        };

        /* Test with no signature schemes
         *
         *= https://raw.githubusercontent.com/FoxIO-LLC/ja4/v0.18.2/technical_details/JA4.md#extension-hash
         *= type=test
         *# If there are no signature algorithms in the hello packet,
         *# then the string ends without an underscore and is hashed.
         */
        {
            /* Extensions exist -- does NOT end in an underscore */
            {
                S2N_INIT_CLIENT_HELLO(bytes,
                        S2N_TEST_CLIENT_HELLO_VERSION,
                        S2N_TEST_CLIENT_HELLO_AFTER_VERSION,
                        S2N_TEST_CLIENT_HELLO_CIPHERS,
                        S2N_TEST_CLIENT_HELLO_AFTER_CIPHERS,
                        /* Add some extensions so that part c isn't completely empty */
                        0x00, 4,
                        0x00, 0x01, S2N_TEST_CLIENT_HELLO_EMPTY_EXTENSION);

                uint8_t output[S2N_TEST_OUTPUT_SIZE] = { 0 };
                uint32_t output_size = 0;
                EXPECT_OK(s2n_test_ja4_raw_from_bytes(bytes, sizeof(bytes),
                        sizeof(output), output, &output_size));

                /* Last character is not an underscore */
                EXPECT_TRUE(output_size > 1);
                EXPECT_NOT_EQUAL(output[output_size - 1], '_');
            };

            /* No extensions -- does end in an underscore */
            {
                S2N_INIT_CLIENT_HELLO(bytes,
                        S2N_TEST_CLIENT_HELLO_VERSION,
                        S2N_TEST_CLIENT_HELLO_AFTER_VERSION,
                        S2N_TEST_CLIENT_HELLO_CIPHERS,
                        S2N_TEST_CLIENT_HELLO_AFTER_CIPHERS,
                        S2N_TEST_CLIENT_HELLO_EMPTY_EXTENSIONS);

                uint8_t output[S2N_TEST_OUTPUT_SIZE] = { 0 };
                uint32_t output_size = 0;
                EXPECT_OK(s2n_test_ja4_raw_from_bytes(bytes, sizeof(bytes),
                        sizeof(output), output, &output_size));

                /* Does end in an underscore */
                EXPECT_TRUE(output_size > 1);
                EXPECT_EQUAL(output[output_size - 1], '_');

                /* We only expect the underscores between parts a, b, and c (a_b_c).
                 * The final underscore should be due to part c being missing
                 * completely, not due to missing signature algorithms.
                 */
                size_t underscore_count = 0;
                for (size_t i = 0; i < output_size; i++) {
                    if (output[i] == '_') {
                        underscore_count++;
                    }
                }
                EXPECT_EQUAL(underscore_count, 2);
            };
        };
    };

    /* Test with malformed extensions
     *
     * Make each extension used by the JA4 algorithm 0-length to test error handling.
     */
    {
        S2N_INIT_CLIENT_HELLO(client_hello_bytes,
                S2N_TEST_CLIENT_HELLO_VERSION,
                S2N_TEST_CLIENT_HELLO_AFTER_VERSION,
                S2N_TEST_CLIENT_HELLO_CIPHERS,
                S2N_TEST_CLIENT_HELLO_AFTER_CIPHERS,
                /* extensions size */
                0x00, (3 * 4),
                /* extensions */
                /* signature_algorithms */
                0x00, 13, S2N_TEST_CLIENT_HELLO_EMPTY_EXTENSION,
                /* application_layer_protocol_negotiation */
                0x00, 16, S2N_TEST_CLIENT_HELLO_EMPTY_EXTENSION,
                /* supported_versions */
                0x00, 43, S2N_TEST_CLIENT_HELLO_EMPTY_EXTENSION);

        uint8_t output[S2N_TEST_OUTPUT_SIZE] = { 0 };
        uint32_t output_size = 0;
        EXPECT_OK(s2n_test_ja4_raw_from_bytes(client_hello_bytes, sizeof(client_hello_bytes),
                sizeof(output), output, &output_size));
    }

    END_TEST();
}
