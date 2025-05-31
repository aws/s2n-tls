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

#include "tls/s2n_fingerprint.h"

#include "api/unstable/fingerprint.h"
#include "crypto/s2n_hash.h"
#include "s2n_test.h"
#include "testlib/s2n_testlib.h"

#define S2N_TEST_HASH S2N_HASH_SHA256
#define TEST_COUNT    10

#define S2N_TEST_OUTPUT_SIZE 100

static S2N_RESULT s2n_test_hash_state_new(struct s2n_hash_state *hash_state)
{
    EXPECT_SUCCESS(s2n_hash_new(hash_state));
    EXPECT_SUCCESS(s2n_hash_init(hash_state, S2N_TEST_HASH));
    return S2N_RESULT_OK;
}

int main(int argc, char **argv)
{
    BEGIN_TEST();

    const char test_char = '!';
    const char test_str[] = "hello";
    const size_t test_str_len = strlen(test_str);
    EXPECT_NOT_EQUAL(test_char, test_str[0]);

    const uint8_t test_str_digest[] = {
        0x2c, 0xf2, 0x4d, 0xba, 0x5f, 0xb0, 0xa3, 0xe, 0x26, 0xe8, 0x3b,
        0x2a, 0xc5, 0xb9, 0xe2, 0x9e, 0x1b, 0x16, 0x1e, 0x5c, 0x1f, 0xa7,
        0x42, 0x5e, 0x73, 0x4, 0x33, 0x62, 0x93, 0x8b, 0x98, 0x24
    };

    /* clang-format off */
    const uint8_t raw_client_hello[] = {
        /* message type */
        TLS_CLIENT_HELLO,
        /* message size */
        0x00, 0x00, 43,
        /* protocol version - TLS1.2 */
        0x03, 0x03,
        /* random */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        /* session id */
        0x00,
        /* cipher suites */
        0x00, 0x02,
        TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        /* legacy compression methods */
        0x01, 0x00,
        /* extensions - empty */
        0x00, 0x00,
    };
    /* clang-format on */
    DEFER_CLEANUP(struct s2n_client_hello *client_hello = NULL, s2n_client_hello_free);
    client_hello = s2n_client_hello_parse_message(raw_client_hello, sizeof(raw_client_hello));
    EXPECT_NOT_NULL(client_hello);
    const uint32_t client_hello_ja3_full_size = 12;

    /* Test s2n_fingerprint_hash_add_char */
    {
        /* Safety */
        EXPECT_ERROR_WITH_ERRNO(s2n_fingerprint_hash_add_char(NULL, test_char),
                S2N_ERR_NULL);

        /* Add to stuffer */
        {
            DEFER_CLEANUP(struct s2n_stuffer output = { 0 }, s2n_stuffer_free);
            EXPECT_SUCCESS(s2n_stuffer_alloc(&output, TEST_COUNT));
            struct s2n_fingerprint_hash hash = { .buffer = &output };

            for (size_t i = 1; i <= TEST_COUNT; i++) {
                EXPECT_OK(s2n_fingerprint_hash_add_char(&hash, test_char));
                EXPECT_EQUAL(s2n_stuffer_data_available(&output), 1);

                char actual_value = 0;
                EXPECT_SUCCESS(s2n_stuffer_read_char(&output, &actual_value));
                EXPECT_EQUAL(actual_value, test_char);
            }
        };

        /* Add to hash */
        {
            DEFER_CLEANUP(struct s2n_hash_state hash_state = { 0 }, s2n_hash_free);
            EXPECT_OK(s2n_test_hash_state_new(&hash_state));
            struct s2n_fingerprint_hash hash = { .hash = &hash_state };

            for (size_t i = 1; i <= TEST_COUNT; i++) {
                EXPECT_OK(s2n_fingerprint_hash_add_char(&hash, test_char));
                EXPECT_EQUAL(hash.hash->currently_in_hash, i);
            }
        };

        /* Error due to insufficient space */
        {
            DEFER_CLEANUP(struct s2n_stuffer output = { 0 }, s2n_stuffer_free);
            struct s2n_fingerprint_hash hash = { .buffer = &output };
            EXPECT_ERROR_WITH_ERRNO(s2n_fingerprint_hash_add_char(&hash, test_char),
                    S2N_ERR_INSUFFICIENT_MEM_SIZE);

            EXPECT_SUCCESS(s2n_stuffer_alloc(&output, 1));
            EXPECT_OK(s2n_fingerprint_hash_add_char(&hash, test_char));
            EXPECT_ERROR_WITH_ERRNO(s2n_fingerprint_hash_add_char(&hash, test_char),
                    S2N_ERR_INSUFFICIENT_MEM_SIZE);
        };
    };

    /* Test s2n_fingerprint_hash_add_str */
    {
        /* Safety */
        {
            /* Null hash */
            EXPECT_ERROR_WITH_ERRNO(s2n_fingerprint_hash_add_str(NULL, test_str, 0),
                    S2N_ERR_NULL);

            /* Null str with stuffer */
            {
                DEFER_CLEANUP(struct s2n_stuffer output = { 0 }, s2n_stuffer_free);
                EXPECT_SUCCESS(s2n_stuffer_alloc(&output, 100));
                struct s2n_fingerprint_hash hash = { .buffer = &output };
                EXPECT_ERROR_WITH_ERRNO(s2n_fingerprint_hash_add_str(&hash, NULL, 10),
                        S2N_ERR_NULL);
                EXPECT_OK(s2n_fingerprint_hash_add_str(&hash, NULL, 0));
            };

            /* Null str with hash */
            {
                DEFER_CLEANUP(struct s2n_hash_state hash_state = { 0 }, s2n_hash_free);
                EXPECT_OK(s2n_test_hash_state_new(&hash_state));
                struct s2n_fingerprint_hash hash = { .hash = &hash_state };
                EXPECT_ERROR_WITH_ERRNO(s2n_fingerprint_hash_add_str(&hash, NULL, 10),
                        S2N_ERR_NULL);
                EXPECT_OK(s2n_fingerprint_hash_add_str(&hash, NULL, 0));
            };
        };

        /* Add to stuffer */
        {
            DEFER_CLEANUP(struct s2n_stuffer output = { 0 }, s2n_stuffer_free);
            EXPECT_SUCCESS(s2n_stuffer_alloc(&output, test_str_len * TEST_COUNT));
            struct s2n_fingerprint_hash hash = { .buffer = &output };

            for (size_t i = 1; i <= TEST_COUNT; i++) {
                EXPECT_OK(s2n_fingerprint_hash_add_str(&hash, test_str, test_str_len));
                EXPECT_EQUAL(s2n_stuffer_data_available(&output), test_str_len);

                uint8_t actual_value[sizeof(test_str)] = { 0 };
                EXPECT_SUCCESS(s2n_stuffer_read_bytes(&output, actual_value, test_str_len));
                EXPECT_BYTEARRAY_EQUAL(actual_value, test_str, test_str_len);
            }
        };

        /* Add to hash */
        {
            DEFER_CLEANUP(struct s2n_hash_state hash_state = { 0 }, s2n_hash_free);
            EXPECT_OK(s2n_test_hash_state_new(&hash_state));
            struct s2n_fingerprint_hash hash = { .hash = &hash_state };

            for (size_t i = 1; i <= TEST_COUNT; i++) {
                EXPECT_OK(s2n_fingerprint_hash_add_str(&hash, test_str, test_str_len));
                EXPECT_EQUAL(hash.hash->currently_in_hash, test_str_len * i);
            }
        };

        /* Error due to insufficient space */
        {
            struct s2n_stuffer output = { 0 };
            struct s2n_fingerprint_hash hash = { .buffer = &output };
            EXPECT_ERROR_WITH_ERRNO(
                    s2n_fingerprint_hash_add_str(&hash, test_str, test_str_len),
                    S2N_ERR_INSUFFICIENT_MEM_SIZE);

            EXPECT_SUCCESS(s2n_stuffer_alloc(&output, 1));
            EXPECT_ERROR_WITH_ERRNO(
                    s2n_fingerprint_hash_add_str(&hash, test_str, test_str_len),
                    S2N_ERR_INSUFFICIENT_MEM_SIZE);
            EXPECT_SUCCESS(s2n_stuffer_free(&output));

            EXPECT_SUCCESS(s2n_stuffer_alloc(&output, test_str_len - 1));
            EXPECT_ERROR_WITH_ERRNO(
                    s2n_fingerprint_hash_add_str(&hash, test_str, test_str_len),
                    S2N_ERR_INSUFFICIENT_MEM_SIZE);
            EXPECT_SUCCESS(s2n_stuffer_free(&output));

            EXPECT_SUCCESS(s2n_stuffer_alloc(&output, test_str_len));
            EXPECT_OK(s2n_fingerprint_hash_add_char(&hash, test_char));
            EXPECT_ERROR_WITH_ERRNO(
                    s2n_fingerprint_hash_add_str(&hash, test_str, test_str_len),
                    S2N_ERR_INSUFFICIENT_MEM_SIZE);
            EXPECT_SUCCESS(s2n_stuffer_free(&output));
        };
    };

    /* Test s2n_fingerprint_hash_digest */
    {
        /* Safety */
        {
            struct s2n_fingerprint_hash hash = { 0 };
            struct s2n_blob output = { 0 };
            EXPECT_ERROR_WITH_ERRNO(s2n_fingerprint_hash_digest(NULL, &output), S2N_ERR_NULL);
            EXPECT_ERROR_WITH_ERRNO(s2n_fingerprint_hash_digest(&hash, NULL), S2N_ERR_NULL);
        };

        /* Digest successfully calculated */
        {
            DEFER_CLEANUP(struct s2n_hash_state hash_state = { 0 }, s2n_hash_free);
            EXPECT_OK(s2n_test_hash_state_new(&hash_state));
            struct s2n_fingerprint_hash hash = { .hash = &hash_state };

            EXPECT_OK(s2n_fingerprint_hash_add_str(&hash, test_str, test_str_len));
            EXPECT_EQUAL(hash.hash->currently_in_hash, test_str_len);

            uint8_t digest_bytes[sizeof(test_str_digest)] = { 0 };
            struct s2n_blob actual_digest = { 0 };
            EXPECT_OK(s2n_blob_init(&actual_digest, digest_bytes, sizeof(digest_bytes)));

            EXPECT_OK(s2n_fingerprint_hash_digest(&hash, &actual_digest));
            EXPECT_BYTEARRAY_EQUAL(test_str_digest, actual_digest.data, actual_digest.size);
            EXPECT_EQUAL(test_str_len, hash.bytes_digested);
        };

        /* Hash can be reused after digest */
        {
            DEFER_CLEANUP(struct s2n_hash_state hash_state = { 0 }, s2n_hash_free);
            EXPECT_OK(s2n_test_hash_state_new(&hash_state));
            struct s2n_fingerprint_hash hash = { .hash = &hash_state };

            const size_t count = 10;
            for (size_t i = 0; i < count; i++) {
                uint8_t digest_bytes[sizeof(test_str_digest)] = { 0 };
                struct s2n_blob actual_digest = { 0 };
                EXPECT_OK(s2n_blob_init(&actual_digest, digest_bytes, sizeof(digest_bytes)));

                EXPECT_OK(s2n_fingerprint_hash_add_str(&hash, test_str, test_str_len));
                EXPECT_OK(s2n_fingerprint_hash_digest(&hash, &actual_digest));

                EXPECT_BYTEARRAY_EQUAL(test_str_digest, actual_digest.data, actual_digest.size);
            }
            EXPECT_EQUAL(hash.bytes_digested, test_str_len * count);
        };
    };

    /* Test s2n_fingerprint_hash_do_digest */
    {
        /* Safety */
        EXPECT_FALSE(s2n_fingerprint_hash_do_digest(NULL));

        struct s2n_fingerprint_hash hash = { 0 };
        EXPECT_FALSE(s2n_fingerprint_hash_do_digest(&hash));

        struct s2n_stuffer output = { 0 };
        hash.buffer = &output;
        EXPECT_FALSE(s2n_fingerprint_hash_do_digest(&hash));

        struct s2n_hash_state hash_state = { 0 };
        hash.hash = &hash_state;
        EXPECT_TRUE(s2n_fingerprint_hash_do_digest(&hash));
    };

    /* Test s2n_assert_grease_value */
    {
        EXPECT_TRUE(s2n_fingerprint_is_grease_value(0x0A0A));
        EXPECT_TRUE(s2n_fingerprint_is_grease_value(0xFAFA));
        EXPECT_FALSE(s2n_fingerprint_is_grease_value(0x0000));
        EXPECT_FALSE(s2n_fingerprint_is_grease_value(0x0001));
    };

    /* Test s2n_fingerprint_new / s2n_fingerprint_free */
    {
        /* New fails for an invalid fingerprint method */
        EXPECT_NULL_WITH_ERRNO(s2n_fingerprint_new(-1), S2N_ERR_INVALID_ARGUMENT);

        /* Free is a no-op for a NULL pointer */
        EXPECT_SUCCESS(s2n_fingerprint_free(NULL));

        /* New succeeds for a valid fingerprint method */
        struct s2n_fingerprint *fingerprint = s2n_fingerprint_new(S2N_FINGERPRINT_JA3);
        EXPECT_NOT_NULL(fingerprint);
        EXPECT_EQUAL(fingerprint->method, &ja3_fingerprint);
        EXPECT_TRUE(s2n_hash_is_ready_for_input(&fingerprint->hash));
        EXPECT_NULL(fingerprint->client_hello);
        EXPECT_EQUAL(fingerprint->raw_size, 0);

        /* Free cleans up the fingerprint */
        EXPECT_SUCCESS(s2n_fingerprint_free(&fingerprint));
        EXPECT_NULL(fingerprint);

        /* Free succeeds again for a freed / NULL fingerprint */
        EXPECT_SUCCESS(s2n_fingerprint_free(&fingerprint));
    };

    /* Test s2n_fingerprint_wipe */
    {
        /* Safety */
        EXPECT_FAILURE_WITH_ERRNO(s2n_fingerprint_wipe(NULL), S2N_ERR_INVALID_ARGUMENT);

        /* Initialize an invalid fingerprint with every field set to all 1s */
        struct s2n_fingerprint fingerprint = { 0 };
        EXPECT_NOT_NULL(memset(&fingerprint, 1, sizeof(struct s2n_fingerprint)));
        EXPECT_NOT_NULL(fingerprint.method);
        EXPECT_TRUE(fingerprint.hash.is_ready_for_input);
        EXPECT_NOT_NULL(fingerprint.client_hello);
        EXPECT_NOT_EQUAL(fingerprint.raw_size, 0);

        /* Verify that wipe only clears the expected fields */
        EXPECT_SUCCESS(s2n_fingerprint_wipe(&fingerprint));
        EXPECT_NOT_NULL(fingerprint.method);
        EXPECT_TRUE(fingerprint.hash.is_ready_for_input);
        EXPECT_NULL(fingerprint.client_hello);
        EXPECT_EQUAL(fingerprint.raw_size, 0);
    };

    /* Test s2n_fingerprint_set_client_hello */
    {
        /* Safety */
        {
            struct s2n_fingerprint fingerprint = { 0 };
            EXPECT_FAILURE_WITH_ERRNO(
                    s2n_fingerprint_set_client_hello(&fingerprint, NULL),
                    S2N_ERR_INVALID_ARGUMENT);
            EXPECT_FAILURE_WITH_ERRNO(
                    s2n_fingerprint_set_client_hello(NULL, client_hello),
                    S2N_ERR_INVALID_ARGUMENT);
        };

        /* SSLv2 not allowed */
        {
            DEFER_CLEANUP(struct s2n_fingerprint *fingerprint = s2n_fingerprint_new(S2N_FINGERPRINT_JA3),
                    s2n_fingerprint_free);
            EXPECT_NOT_NULL(fingerprint);

            struct s2n_client_hello sslv2_client_hello = *client_hello;
            sslv2_client_hello.sslv2 = true;

            EXPECT_FAILURE_WITH_ERRNO(
                    s2n_fingerprint_set_client_hello(fingerprint, &sslv2_client_hello),
                    S2N_ERR_PROTOCOL_VERSION_UNSUPPORTED);
        };

        /* Success */
        {
            DEFER_CLEANUP(struct s2n_fingerprint *fingerprint = s2n_fingerprint_new(S2N_FINGERPRINT_JA3),
                    s2n_fingerprint_free);
            EXPECT_NOT_NULL(fingerprint);
            EXPECT_SUCCESS(s2n_fingerprint_set_client_hello(fingerprint, client_hello));
            EXPECT_EQUAL(fingerprint->client_hello, client_hello);
        };

        /* Other values reset */
        {
            struct s2n_fingerprint fingerprint = { 0 };

            /* Initialize an invalid fingerprint with every field set to all 1s */
            EXPECT_NOT_NULL(memset(&fingerprint, 1, sizeof(struct s2n_fingerprint)));
            EXPECT_NOT_EQUAL(fingerprint.client_hello, client_hello);
            EXPECT_NOT_EQUAL(fingerprint.raw_size, 0);

            /* Setting the client hello resets stateful values */
            EXPECT_SUCCESS(s2n_fingerprint_set_client_hello(&fingerprint, client_hello));
            EXPECT_EQUAL(fingerprint.client_hello, client_hello);
            EXPECT_EQUAL(fingerprint.raw_size, 0);
        };
    };

    /* Test s2n_fingerprint_get_hash_size */
    {
        /* Safety */
        {
            DEFER_CLEANUP(struct s2n_fingerprint *fingerprint = s2n_fingerprint_new(S2N_FINGERPRINT_JA3),
                    s2n_fingerprint_free);

            EXPECT_FAILURE_WITH_ERRNO(
                    s2n_fingerprint_get_hash_size(fingerprint, NULL),
                    S2N_ERR_INVALID_ARGUMENT);

            uint32_t size = 0;
            EXPECT_FAILURE_WITH_ERRNO(
                    s2n_fingerprint_get_hash_size(NULL, &size),
                    S2N_ERR_INVALID_ARGUMENT);
        };

        /* Success */
        {
            DEFER_CLEANUP(struct s2n_fingerprint *fingerprint = s2n_fingerprint_new(S2N_FINGERPRINT_JA3),
                    s2n_fingerprint_free);
            uint32_t actual_size = 0;
            EXPECT_SUCCESS(s2n_fingerprint_get_hash_size(fingerprint, &actual_size));
            EXPECT_EQUAL(actual_size, ja3_fingerprint.hash_str_size);
        };
    };

    /* Test s2n_fingerprint_get_hash */
    {
        /* Safety */
        {
            DEFER_CLEANUP(struct s2n_fingerprint *fingerprint = s2n_fingerprint_new(S2N_FINGERPRINT_JA3),
                    s2n_fingerprint_free);
            uint8_t output[S2N_TEST_OUTPUT_SIZE] = { 0 };
            uint32_t output_size = 0;

            EXPECT_FAILURE_WITH_ERRNO(
                    s2n_fingerprint_get_hash(NULL, sizeof(output), output, &output_size),
                    S2N_ERR_INVALID_ARGUMENT);
            EXPECT_FAILURE_WITH_ERRNO(
                    s2n_fingerprint_get_hash(fingerprint, sizeof(output), NULL, &output_size),
                    S2N_ERR_INVALID_ARGUMENT);
            EXPECT_FAILURE_WITH_ERRNO(
                    s2n_fingerprint_get_hash(fingerprint, sizeof(output), output, NULL),
                    S2N_ERR_INVALID_ARGUMENT);
        };

        /* No ClientHello set */
        {
            DEFER_CLEANUP(struct s2n_fingerprint *fingerprint = s2n_fingerprint_new(S2N_FINGERPRINT_JA3),
                    s2n_fingerprint_free);
            uint8_t output[S2N_TEST_OUTPUT_SIZE] = { 0 };
            uint32_t output_size = 0;

            EXPECT_FAILURE_WITH_ERRNO(
                    s2n_fingerprint_get_hash(fingerprint, sizeof(output), output, &output_size),
                    S2N_ERR_INVALID_STATE);
        };

        /* Success */
        {
            DEFER_CLEANUP(struct s2n_fingerprint *fingerprint = s2n_fingerprint_new(S2N_FINGERPRINT_JA3),
                    s2n_fingerprint_free);
            EXPECT_SUCCESS(s2n_fingerprint_set_client_hello(fingerprint, client_hello));

            uint8_t output[S2N_TEST_OUTPUT_SIZE] = { 0 };
            uint32_t output_size = 0;
            EXPECT_SUCCESS(s2n_fingerprint_get_hash(fingerprint,
                    sizeof(output), output, &output_size));

            EXPECT_EQUAL(output_size, ja3_fingerprint.hash_str_size);
        };

        /* Insufficient memory */
        {
            DEFER_CLEANUP(struct s2n_fingerprint *fingerprint = s2n_fingerprint_new(S2N_FINGERPRINT_JA3),
                    s2n_fingerprint_free);
            EXPECT_SUCCESS(s2n_fingerprint_set_client_hello(fingerprint, client_hello));

            uint8_t output[S2N_TEST_OUTPUT_SIZE] = { 0 };
            uint32_t output_size = 0;
            EXPECT_TRUE(ja3_fingerprint.hash_str_size <= sizeof(output));

            EXPECT_FAILURE_WITH_ERRNO(
                    s2n_fingerprint_get_hash(fingerprint, 0, output, &output_size),
                    S2N_ERR_INSUFFICIENT_MEM_SIZE);
            EXPECT_FAILURE_WITH_ERRNO(
                    s2n_fingerprint_get_hash(fingerprint, ja3_fingerprint.hash_str_size - 1, output, &output_size),
                    S2N_ERR_INSUFFICIENT_MEM_SIZE);
            EXPECT_SUCCESS(
                    s2n_fingerprint_get_hash(fingerprint, ja3_fingerprint.hash_str_size, output, &output_size));
        };
    };

    /* Test s2n_fingerprint_get_raw_size */
    {
        /* Safety */
        {
            DEFER_CLEANUP(struct s2n_fingerprint *fingerprint = s2n_fingerprint_new(S2N_FINGERPRINT_JA3),
                    s2n_fingerprint_free);

            EXPECT_FAILURE_WITH_ERRNO(
                    s2n_fingerprint_get_raw_size(fingerprint, NULL),
                    S2N_ERR_INVALID_ARGUMENT);

            uint32_t size = 0;
            EXPECT_FAILURE_WITH_ERRNO(
                    s2n_fingerprint_get_raw_size(NULL, &size),
                    S2N_ERR_INVALID_ARGUMENT);
        };

        /* Raw size not yet calculated */
        {
            DEFER_CLEANUP(struct s2n_fingerprint *fingerprint = s2n_fingerprint_new(S2N_FINGERPRINT_JA3),
                    s2n_fingerprint_free);
            uint32_t actual_size = 0;
            EXPECT_FAILURE_WITH_ERRNO(
                    s2n_fingerprint_get_raw_size(fingerprint, &actual_size),
                    S2N_ERR_INVALID_STATE);
        };

        /* Success */
        {
            DEFER_CLEANUP(struct s2n_fingerprint *fingerprint = s2n_fingerprint_new(S2N_FINGERPRINT_JA3),
                    s2n_fingerprint_free);
            EXPECT_SUCCESS(s2n_fingerprint_set_client_hello(fingerprint, client_hello));

            uint8_t hash[S2N_TEST_OUTPUT_SIZE] = { 0 };
            uint32_t hash_size = 0;
            EXPECT_SUCCESS(s2n_fingerprint_get_hash(fingerprint,
                    sizeof(hash), hash, &hash_size));

            uint32_t raw_size = 0;
            EXPECT_SUCCESS(s2n_fingerprint_get_raw_size(fingerprint, &raw_size));
            EXPECT_EQUAL(raw_size, client_hello_ja3_full_size);
        };
    };

    /* Test s2n_fingerprint_get_raw */
    {
        /* Safety */
        {
            DEFER_CLEANUP(struct s2n_fingerprint *fingerprint = s2n_fingerprint_new(S2N_FINGERPRINT_JA3),
                    s2n_fingerprint_free);
            uint8_t output[S2N_TEST_OUTPUT_SIZE] = { 0 };
            uint32_t output_size = 0;

            EXPECT_FAILURE_WITH_ERRNO(
                    s2n_fingerprint_get_raw(NULL, sizeof(output), output, &output_size),
                    S2N_ERR_INVALID_ARGUMENT);
            EXPECT_FAILURE_WITH_ERRNO(
                    s2n_fingerprint_get_raw(fingerprint, sizeof(output), NULL, &output_size),
                    S2N_ERR_INVALID_ARGUMENT);
            EXPECT_FAILURE_WITH_ERRNO(
                    s2n_fingerprint_get_raw(fingerprint, sizeof(output), output, NULL),
                    S2N_ERR_INVALID_ARGUMENT);
        };

        /* Success */
        {
            DEFER_CLEANUP(struct s2n_fingerprint *fingerprint = s2n_fingerprint_new(S2N_FINGERPRINT_JA3),
                    s2n_fingerprint_free);
            EXPECT_SUCCESS(s2n_fingerprint_set_client_hello(fingerprint, client_hello));

            uint8_t output[S2N_TEST_OUTPUT_SIZE] = { 0 };
            uint32_t output_size = 0;
            EXPECT_SUCCESS(s2n_fingerprint_get_raw(fingerprint,
                    sizeof(output), output, &output_size));

            EXPECT_EQUAL(output_size, client_hello_ja3_full_size);
        };

        /* Insufficient memory */
        {
            DEFER_CLEANUP(struct s2n_fingerprint *fingerprint = s2n_fingerprint_new(S2N_FINGERPRINT_JA3),
                    s2n_fingerprint_free);
            EXPECT_SUCCESS(s2n_fingerprint_set_client_hello(fingerprint, client_hello));

            uint8_t output[S2N_TEST_OUTPUT_SIZE] = { 0 };
            uint32_t output_size = 0;
            EXPECT_TRUE(client_hello_ja3_full_size <= sizeof(output));

            EXPECT_FAILURE_WITH_ERRNO(
                    s2n_fingerprint_get_raw(fingerprint, 0, output, &output_size),
                    S2N_ERR_INSUFFICIENT_MEM_SIZE);
            EXPECT_FAILURE_WITH_ERRNO(
                    s2n_fingerprint_get_raw(fingerprint, client_hello_ja3_full_size - 1, output, &output_size),
                    S2N_ERR_INSUFFICIENT_MEM_SIZE);
            EXPECT_SUCCESS(
                    s2n_fingerprint_get_raw(fingerprint, client_hello_ja3_full_size, output, &output_size));
        };
    };

    /* Test new s2n_fingerprint methods match old s2n_client_hello_get_fingerprint_hash method */
    {
        DEFER_CLEANUP(struct s2n_fingerprint *fingerprint = s2n_fingerprint_new(S2N_FINGERPRINT_JA3),
                s2n_fingerprint_free);
        EXPECT_SUCCESS(s2n_fingerprint_set_client_hello(fingerprint, client_hello));

        uint8_t legacy_output[S2N_TEST_OUTPUT_SIZE] = { 0 };
        uint32_t legacy_output_size = 0;
        uint32_t legacy_raw_size = 0;
        EXPECT_SUCCESS(s2n_client_hello_get_fingerprint_hash(client_hello, S2N_FINGERPRINT_JA3,
                sizeof(legacy_output), legacy_output, &legacy_output_size, &legacy_raw_size));

        /* output matches s2n_fingerprint_get_hash */
        {
            uint8_t output[S2N_TEST_OUTPUT_SIZE] = { 0 };
            uint32_t output_size = 0;
            EXPECT_SUCCESS(s2n_fingerprint_get_hash(fingerprint,
                    sizeof(output), output, &output_size));

            struct s2n_stuffer output_stuffer = { 0 };
            EXPECT_OK(s2n_blob_init(&output_stuffer.blob, output, output_size));
            EXPECT_SUCCESS(s2n_stuffer_skip_write(&output_stuffer, output_size));

            /* Legacy output is raw bytes, but new output is hex */
            EXPECT_EQUAL(output_size, legacy_output_size * 2);
            for (size_t i = 0; i < legacy_output_size; i++) {
                uint8_t output_byte = 0;
                EXPECT_OK(s2n_stuffer_read_uint8_hex(&output_stuffer, &output_byte));
                EXPECT_EQUAL(output_byte, legacy_output[i]);
            }
        };

        /* output size matches s2n_fingerprint_get_hash_size */
        {
            uint32_t hash_size = 0;
            EXPECT_SUCCESS(s2n_fingerprint_get_hash_size(fingerprint, &hash_size));
            EXPECT_EQUAL(hash_size, legacy_output_size * 2);
        };

        /* raw size matches s2n_fingerprint_get_raw_size */
        {
            uint32_t raw_size = 0;
            EXPECT_SUCCESS(s2n_fingerprint_get_raw_size(fingerprint, &raw_size));
            EXPECT_EQUAL(raw_size, legacy_raw_size);
        };
    };

    /* Test new s2n_fingerprint methods match old s2n_client_hello_get_fingerprint_string method */
    {
        DEFER_CLEANUP(struct s2n_fingerprint *fingerprint = s2n_fingerprint_new(S2N_FINGERPRINT_JA3),
                s2n_fingerprint_free);
        EXPECT_SUCCESS(s2n_fingerprint_set_client_hello(fingerprint, client_hello));

        uint8_t legacy_output[S2N_TEST_OUTPUT_SIZE] = { 0 };
        uint32_t legacy_output_size = 0;
        EXPECT_SUCCESS(s2n_client_hello_get_fingerprint_string(client_hello, S2N_FINGERPRINT_JA3,
                sizeof(legacy_output), legacy_output, &legacy_output_size));

        /* output matches s2n_fingerprint_get_raw */
        {
            uint8_t output[S2N_TEST_OUTPUT_SIZE] = { 0 };
            uint32_t output_size = 0;
            EXPECT_SUCCESS(s2n_fingerprint_get_raw(fingerprint,
                    sizeof(output), output, &output_size));

            EXPECT_EQUAL(output_size, legacy_output_size);
            EXPECT_BYTEARRAY_EQUAL(output, legacy_output, legacy_output_size);
        };

        /* output size matches s2n_fingerprint_get_raw_size */
        {
            uint32_t raw_size = 0;
            EXPECT_SUCCESS(s2n_fingerprint_get_raw_size(fingerprint, &raw_size));
            EXPECT_EQUAL(raw_size, legacy_output_size);
        };
    };

    /* Test reusing fingerprint structures */
    {
        DEFER_CLEANUP(struct s2n_fingerprint *fingerprint = s2n_fingerprint_new(S2N_FINGERPRINT_JA3),
                s2n_fingerprint_free);

        uint8_t raw_client_hello_2[sizeof(raw_client_hello)] = { 0 };
        EXPECT_MEMCPY_SUCCESS(raw_client_hello_2, raw_client_hello, sizeof(raw_client_hello));
        /* Make a minor change so that we will calculate a different fingerprint.
         * This changes the protocol version from 1.2 to 1.3. */
        raw_client_hello_2[5] = 0x04;

        DEFER_CLEANUP(struct s2n_client_hello *client_hello_2 = NULL, s2n_client_hello_free);
        client_hello_2 = s2n_client_hello_parse_message(raw_client_hello_2, sizeof(raw_client_hello_2));
        EXPECT_NOT_NULL(client_hello_2);

        struct s2n_test_hello {
            struct s2n_client_hello *hello;
            uint8_t hash[S2N_TEST_OUTPUT_SIZE];
            uint8_t raw[S2N_TEST_OUTPUT_SIZE];
            unsigned int init : 1;
        } hellos[] = {
            { .hello = client_hello },
            { .hello = client_hello_2 },
        };

        for (size_t i = 0; i < 10; i++) {
            struct s2n_test_hello *test_case = &hellos[i % s2n_array_len(hellos)];
            EXPECT_SUCCESS(s2n_fingerprint_set_client_hello(fingerprint, test_case->hello));

            /* Verify no state leftover after reset */
            uint32_t size = 0;
            EXPECT_FAILURE_WITH_ERRNO(
                    s2n_fingerprint_get_raw_size(fingerprint, &size),
                    S2N_ERR_INVALID_STATE);

            /* Store initial copy of hash / raw string for later comparisons */
            if (test_case->init == false) {
                test_case->init = true;
                EXPECT_SUCCESS(s2n_fingerprint_get_hash(fingerprint,
                        sizeof(test_case->hash), test_case->hash, &size));
                EXPECT_SUCCESS(s2n_fingerprint_get_raw(fingerprint,
                        sizeof(test_case->raw), test_case->raw, &size));
            }

            /* Verify all hash calculations match across resets */
            uint8_t hash_output[S2N_TEST_OUTPUT_SIZE] = { 0 };
            EXPECT_SUCCESS(s2n_fingerprint_get_hash(fingerprint,
                    sizeof(hash_output), hash_output, &size));
            EXPECT_BYTEARRAY_EQUAL(hash_output, test_case->hash, S2N_TEST_OUTPUT_SIZE);

            /* Verify all raw string calculations match across resets */
            uint8_t raw_output[S2N_TEST_OUTPUT_SIZE] = { 0 };
            EXPECT_SUCCESS(s2n_fingerprint_get_raw(fingerprint,
                    sizeof(raw_output), raw_output, &size));
            EXPECT_BYTEARRAY_EQUAL(raw_output, test_case->raw, S2N_TEST_OUTPUT_SIZE);

            /* Reset for the next iteration */
            EXPECT_SUCCESS(s2n_fingerprint_wipe(fingerprint));
        }

        /* Verify that we actually tested with different hellos */
        EXPECT_BYTEARRAY_NOT_EQUAL(hellos[0].hash, hellos[1].hash, S2N_TEST_OUTPUT_SIZE);
        EXPECT_BYTEARRAY_NOT_EQUAL(hellos[0].raw, hellos[1].raw, S2N_TEST_OUTPUT_SIZE);
    };

    END_TEST();
}
