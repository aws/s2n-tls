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
#include "crypto/s2n_fips.h"
#include "s2n_test.h"
#include "testlib/s2n_sslv2_client_hello.h"
#include "testlib/s2n_testlib.h"
#include "tls/s2n_tls.h"

/* SSLv2 == 0x0200 == 512 */
#define S2N_JA3_SSLV2_VAL 512

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

#define S2N_TEST_CLIENT_HELLO_AFTER_CIPHERS \
    /* legacy compression methods */        \
    0x01, 0x00

/* This macro currently assumes that the message size is only one byte (<=255). */
#define S2N_INIT_CLIENT_HELLO(name, ...)                 \
    uint8_t _##name##_message[] = { __VA_ARGS__ };       \
    EXPECT_TRUE(sizeof(_##name##_message) <= UINT8_MAX); \
    uint8_t name[] = {                                   \
        TLS_CLIENT_HELLO,                                \
        0x00, 0x00, sizeof(_##name##_message),           \
        __VA_ARGS__                                      \
    }

typedef enum {
    S2N_CH_FROM_IO = 0,
    S2N_CH_FROM_RAW,
} s2n_ch_source;

static S2N_RESULT s2n_validate_ja3_str_list(struct s2n_stuffer *input)
{
    uint32_t skipped = 0;
    size_t count = 0;
    DEFER_CLEANUP(struct s2n_stuffer list = { 0 }, s2n_stuffer_free);
    RESULT_GUARD_POSIX(s2n_stuffer_growable_alloc(&list, 0));
    RESULT_GUARD_POSIX(s2n_stuffer_read_token(input, &list, ','));
    while (s2n_stuffer_data_available(&list)) {
        RESULT_GUARD_POSIX(s2n_stuffer_skip_to_char(&list, '-'));
        RESULT_GUARD_POSIX(s2n_stuffer_skip_expected_char(&list, '-',
                0, 1, &skipped));
        count++;
    }
    RESULT_ENSURE_GT(count, 1);
    return S2N_RESULT_OK;
}

static S2N_RESULT s2n_validate_ja3_str(uint8_t *ja3, uint32_t ja3_size,
        const char *expected_version)
{
    struct s2n_blob input_blob = { 0 };
    struct s2n_stuffer input = { 0 };
    RESULT_GUARD_POSIX(s2n_blob_init(&input_blob, ja3, ja3_size));
    RESULT_GUARD_POSIX(s2n_stuffer_init(&input, &input_blob));
    RESULT_GUARD_POSIX(s2n_stuffer_skip_write(&input, ja3_size));

    /* Expect the provided version */
    RESULT_GUARD_POSIX(s2n_stuffer_read_expected_str(&input, expected_version));
    RESULT_GUARD_POSIX(s2n_stuffer_read_expected_str(&input, ","));

    /* Expect at least one entry in the cipher list */
    RESULT_GUARD(s2n_validate_ja3_str_list(&input));

    /* Expect at least one entry in the extensions list */
    RESULT_GUARD(s2n_validate_ja3_str_list(&input));

    /* Expect at least one entry in the curves list */
    RESULT_GUARD(s2n_validate_ja3_str_list(&input));

    /* Expect only one point format: 0 / uncompressed */
    RESULT_GUARD_POSIX(s2n_stuffer_read_expected_str(&input, "0"));

    RESULT_ENSURE_EQ(s2n_stuffer_data_available(&input), 0);
    return S2N_RESULT_OK;
}

static S2N_RESULT s2n_client_hello_from_source(struct s2n_client_hello **client_hello,
        struct s2n_connection *server, uint8_t *input, uint32_t input_size, s2n_ch_source source)
{
    switch (source) {
        case S2N_CH_FROM_IO:
            RESULT_GUARD_POSIX(s2n_connection_wipe(server));
            RESULT_GUARD_POSIX(s2n_stuffer_write_bytes(&server->handshake.io,
                    input + TLS_HANDSHAKE_HEADER_LENGTH, input_size - TLS_HANDSHAKE_HEADER_LENGTH));
            RESULT_GUARD_POSIX(s2n_client_hello_recv(server));
            *client_hello = s2n_connection_get_client_hello(server);
            RESULT_ENSURE_REF(*client_hello);
            break;
        case S2N_CH_FROM_RAW:
            *client_hello = s2n_client_hello_parse_message(input, input_size);
            RESULT_GUARD_PTR(*client_hello);
            break;
    }
    return S2N_RESULT_OK;
}

int main(int argc, char **argv)
{
    BEGIN_TEST();

    uint8_t output_mem[500] = { 0 };
    s2n_ch_source sources[] = {
        S2N_CH_FROM_IO,
        S2N_CH_FROM_RAW,
    };

    DEFER_CLEANUP(struct s2n_cert_chain_and_key *chain_and_key = NULL,
            s2n_cert_chain_and_key_ptr_free);
    EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&chain_and_key,
            S2N_DEFAULT_TEST_CERT_CHAIN, S2N_DEFAULT_TEST_PRIVATE_KEY));

    DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
    EXPECT_NOT_NULL(config);
    EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, chain_and_key));
    EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, "test_all"));

    uint8_t empty_md5_hash[MD5_DIGEST_LENGTH] = { 0 };
    DEFER_CLEANUP(struct s2n_hash_state md5_hash = { 0 }, s2n_hash_free);
    EXPECT_SUCCESS(s2n_hash_new(&md5_hash));
    if (s2n_is_in_fips_mode()) {
        EXPECT_SUCCESS(s2n_hash_allow_md5_for_fips(&md5_hash));
    }
    EXPECT_SUCCESS(s2n_hash_init(&md5_hash, S2N_HASH_MD5));
    EXPECT_SUCCESS(s2n_hash_digest(&md5_hash, empty_md5_hash, MD5_DIGEST_LENGTH));

    /* Test: safety / input validation */
    {
        DEFER_CLEANUP(struct s2n_connection *server = s2n_connection_new(S2N_SERVER),
                s2n_connection_ptr_free);
        struct s2n_client_hello *client_hello = &server->client_hello;
        uint32_t output_size = 0, str_size = 0;

        /* Valid client hello required */
        EXPECT_FAILURE_WITH_ERRNO(
                s2n_client_hello_get_fingerprint_string(NULL, S2N_FINGERPRINT_JA3,
                        sizeof(output_mem), output_mem, &output_size),
                S2N_ERR_NULL);
        EXPECT_FAILURE_WITH_ERRNO(
                s2n_client_hello_get_fingerprint_hash(NULL, S2N_FINGERPRINT_JA3,
                        sizeof(output_mem), output_mem, &output_size, &str_size),
                S2N_ERR_NULL);

        /* Valid output buffer required */
        EXPECT_FAILURE_WITH_ERRNO(
                s2n_client_hello_get_fingerprint_string(client_hello, S2N_FINGERPRINT_JA3,
                        sizeof(output_mem), NULL, &output_size),
                S2N_ERR_NULL);
        EXPECT_FAILURE_WITH_ERRNO(
                s2n_client_hello_get_fingerprint_hash(client_hello, S2N_FINGERPRINT_JA3,
                        sizeof(output_mem), NULL, &output_size, &str_size),
                S2N_ERR_NULL);
        EXPECT_FAILURE_WITH_ERRNO(
                s2n_client_hello_get_fingerprint_string(client_hello, S2N_FINGERPRINT_JA3,
                        0, NULL, &output_size),
                S2N_ERR_INSUFFICIENT_MEM_SIZE);
        EXPECT_FAILURE_WITH_ERRNO(
                s2n_client_hello_get_fingerprint_hash(client_hello, S2N_FINGERPRINT_JA3,
                        0, NULL, &output_size, &str_size),
                S2N_ERR_INSUFFICIENT_MEM_SIZE);

        /* Valid size ptr required */
        EXPECT_FAILURE_WITH_ERRNO(
                s2n_client_hello_get_fingerprint_string(client_hello, S2N_FINGERPRINT_JA3,
                        sizeof(output_mem), output_mem, NULL),
                S2N_ERR_NULL);
        EXPECT_FAILURE_WITH_ERRNO(
                s2n_client_hello_get_fingerprint_hash(client_hello, S2N_FINGERPRINT_JA3,
                        sizeof(output_mem), output_mem, NULL, &str_size),
                S2N_ERR_NULL);
        EXPECT_FAILURE_WITH_ERRNO(
                s2n_client_hello_get_fingerprint_hash(client_hello, S2N_FINGERPRINT_JA3,
                        sizeof(output_mem), output_mem, &output_size, NULL),
                S2N_ERR_NULL);

        /* Only JA3 currently supported */
        EXPECT_FAILURE_WITH_ERRNO(
                s2n_client_hello_get_fingerprint_string(client_hello, S2N_FINGERPRINT_JA3 + 1,
                        sizeof(output_mem), output_mem, &output_size),
                S2N_ERR_INVALID_ARGUMENT);
        EXPECT_FAILURE_WITH_ERRNO(
                s2n_client_hello_get_fingerprint_hash(client_hello, S2N_FINGERPRINT_JA3 + 1,
                        sizeof(output_mem), output_mem, &output_size, &str_size),
                S2N_ERR_INVALID_ARGUMENT);
    };

    /* Test: ja3 string */
    {
        /* Test: basic case */
        {
            DEFER_CLEANUP(struct s2n_connection *client = s2n_connection_new(S2N_CLIENT),
                    s2n_connection_ptr_free);
            EXPECT_NOT_NULL(client);

            DEFER_CLEANUP(struct s2n_connection *server = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            EXPECT_NOT_NULL(server);
            EXPECT_SUCCESS(s2n_connection_set_config(server, config));

            EXPECT_SUCCESS(s2n_client_hello_send(client));
            EXPECT_SUCCESS(s2n_stuffer_copy(&client->handshake.io, &server->handshake.io,
                    s2n_stuffer_data_available(&client->handshake.io)));
            EXPECT_SUCCESS(s2n_client_hello_recv(server));

            struct s2n_client_hello *client_hello = s2n_connection_get_client_hello(server);
            EXPECT_NOT_NULL(client_hello);
            EXPECT_FALSE(client_hello->sslv2);

            uint32_t output_size = 0;
            EXPECT_SUCCESS(s2n_client_hello_get_fingerprint_string(client_hello,
                    S2N_FINGERPRINT_JA3, sizeof(output_mem), output_mem, &output_size));

            /* Expect valid ja3.
             * TLS1.2 == 0x0303 == 771 */
            EXPECT_OK(s2n_validate_ja3_str(output_mem, output_size, "771"));
        };

        /* Test: SSLv2 not supported */
        {
            DEFER_CLEANUP(struct s2n_connection *server = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            EXPECT_NOT_NULL(server);
            EXPECT_SUCCESS(s2n_connection_set_config(server, config));
            EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(server, "test_all"));

            /* SSLv2 ClientHellos are used by clients as a backwards-compatible attempt
             * to communicate with servers that don't support later versions.
             * s2n-tls DOES support later versions, so requires that SSLv2 ClientHellos
             * advertise a higher version.
             *
             * This version negotiation is done when processing the record,
             * not when processing the actual ClientHello message.
             * So we need to set the versions manually.
             */
            server->client_hello_version = S2N_SSLv2;
            server->client_protocol_version = S2N_TLS12;

            uint8_t sslv2_client_hello[] = {
                SSLv2_CLIENT_HELLO_PREFIX,
                SSLv2_CLIENT_HELLO_CIPHER_SUITES,
                SSLv2_CLIENT_HELLO_CHALLENGE,
            };
            EXPECT_SUCCESS(s2n_stuffer_write_bytes(&server->handshake.io,
                    sslv2_client_hello, sizeof(sslv2_client_hello)));
            EXPECT_SUCCESS(s2n_client_hello_recv(server));

            struct s2n_client_hello *client_hello = s2n_connection_get_client_hello(server);
            EXPECT_NOT_NULL(client_hello);
            EXPECT_TRUE(client_hello->sslv2);

            uint32_t output_size = 0;
            EXPECT_FAILURE_WITH_ERRNO(
                    s2n_client_hello_get_fingerprint_string(client_hello,
                            S2N_FINGERPRINT_JA3, sizeof(output_mem), output_mem, &output_size),
                    S2N_ERR_PROTOCOL_VERSION_UNSUPPORTED);
            EXPECT_EQUAL(output_size, 0);
        };

        /* Test: single entry lists */
        for (size_t i = 0; i < s2n_array_len(sources); i++) {
            s2n_ch_source source = sources[i];

            S2N_INIT_CLIENT_HELLO(client_hello_bytes,
                    /* protocol version */
                    0x03, 0x02,
                    S2N_TEST_CLIENT_HELLO_AFTER_VERSION,
                    /* cipher suites size */
                    0x00, 0x02,
                    /* cipher suites */
                    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                    S2N_TEST_CLIENT_HELLO_AFTER_CIPHERS,
                    /* extensions size */
                    0x00, 0x08,
                    /* extension: supported groups */
                    0x00, TLS_EXTENSION_SUPPORTED_GROUPS, 0x00, 0x04,
                    0x00, 0x02, 0x00, TLS_EC_CURVE_SECP_256_R1);
            const uint8_t expected_ja3[] = "770,49199,10,23,";
            size_t expected_ja3_size = strlen((const char *) expected_ja3);

            DEFER_CLEANUP(struct s2n_connection *server = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            EXPECT_NOT_NULL(server);
            EXPECT_SUCCESS(s2n_connection_set_config(server, config));
            EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(server, "test_all"));

            DEFER_CLEANUP(struct s2n_client_hello *client_hello = NULL,
                    s2n_client_hello_free);
            EXPECT_OK(s2n_client_hello_from_source(&client_hello, server,
                    client_hello_bytes, sizeof(client_hello_bytes), source));

            uint32_t output_size = 0;
            EXPECT_SUCCESS(s2n_client_hello_get_fingerprint_string(client_hello,
                    S2N_FINGERPRINT_JA3, expected_ja3_size, output_mem, &output_size));
            EXPECT_EQUAL(output_size, expected_ja3_size);
            EXPECT_BYTEARRAY_EQUAL(expected_ja3, output_mem, output_size);
        };

        /* Test: missing fields
         *
         * We have to provide a protocol version and one cipher suite
         * in order for the ClientHello to be considered valid, but all
         * other fields can be empty.
         */
        for (size_t i = 0; i < s2n_array_len(sources); i++) {
            s2n_ch_source source = sources[i];

            S2N_INIT_CLIENT_HELLO(client_hello_bytes,
                    /* protocol version */
                    0x03, 0x01,
                    S2N_TEST_CLIENT_HELLO_AFTER_VERSION,
                    /* cipher suites size */
                    0x00, 0x02,
                    /* cipher suites */
                    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                    S2N_TEST_CLIENT_HELLO_AFTER_CIPHERS,
                    /* extensions size */
                    0x00, 0x00);
            const uint8_t expected_ja3[] = "769,49199,,,";
            size_t expected_ja3_size = strlen((const char *) expected_ja3);

            DEFER_CLEANUP(struct s2n_connection *server = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            EXPECT_NOT_NULL(server);
            EXPECT_SUCCESS(s2n_connection_set_config(server, config));
            EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(server, "test_all"));

            DEFER_CLEANUP(struct s2n_client_hello *client_hello = NULL,
                    s2n_client_hello_free);
            EXPECT_OK(s2n_client_hello_from_source(&client_hello, server,
                    client_hello_bytes, sizeof(client_hello_bytes), source));

            uint32_t output_size = 0;
            EXPECT_SUCCESS(s2n_client_hello_get_fingerprint_string(client_hello,
                    S2N_FINGERPRINT_JA3, expected_ja3_size, output_mem, &output_size));
            EXPECT_EQUAL(output_size, expected_ja3_size);
            EXPECT_BYTEARRAY_EQUAL(expected_ja3, output_mem, output_size);
        };

        /* Test: fails if insufficient memory */
        {
            DEFER_CLEANUP(struct s2n_connection *client = s2n_connection_new(S2N_CLIENT),
                    s2n_connection_ptr_free);
            EXPECT_NOT_NULL(client);

            DEFER_CLEANUP(struct s2n_connection *server = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            EXPECT_NOT_NULL(server);
            EXPECT_SUCCESS(s2n_connection_set_config(server, config));

            EXPECT_SUCCESS(s2n_client_hello_send(client));
            EXPECT_SUCCESS(s2n_stuffer_copy(&client->handshake.io, &server->handshake.io,
                    s2n_stuffer_data_available(&client->handshake.io)));
            EXPECT_SUCCESS(s2n_client_hello_recv(server));

            struct s2n_client_hello *client_hello = s2n_connection_get_client_hello(server);
            EXPECT_NOT_NULL(client_hello);

            uint32_t output_size = 0;
            for (size_t i = 0; i < 10; i++) {
                EXPECT_FAILURE_WITH_ERRNO(
                        s2n_client_hello_get_fingerprint_string(client_hello,
                                S2N_FINGERPRINT_JA3, i, output_mem, &output_size),
                        S2N_ERR_INSUFFICIENT_MEM_SIZE);
                EXPECT_EQUAL(output_size, 0);
            }
        };

        /* Test: grease values ignored */
        for (size_t i = 0; i < s2n_array_len(sources); i++) {
            s2n_ch_source source = sources[i];

            const uint8_t grease_value = 0x0A;
            S2N_INIT_CLIENT_HELLO(client_hello_bytes,
                    /* protocol version */
                    0x03, 0x02,
                    S2N_TEST_CLIENT_HELLO_AFTER_VERSION,
                    /* cipher suites size */
                    0x00, 0x04,
                    /* cipher suites */
                    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                    grease_value, grease_value,
                    S2N_TEST_CLIENT_HELLO_AFTER_CIPHERS,
                    /* extensions size */
                    0x00, 0x0E,
                    /* extension: grease */
                    grease_value, grease_value, 0x00, 0x00,
                    /* extension: supported groups */
                    0x00, TLS_EXTENSION_SUPPORTED_GROUPS, 0x00, 0x06,
                    0x00, 0x04, 0x00, TLS_EC_CURVE_SECP_256_R1, grease_value, grease_value);
            const uint8_t expected_ja3[] = "770,49199,10,23,";
            size_t expected_ja3_size = strlen((const char *) expected_ja3);

            DEFER_CLEANUP(struct s2n_connection *server = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            EXPECT_NOT_NULL(server);
            EXPECT_SUCCESS(s2n_connection_set_config(server, config));
            EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(server, "test_all"));

            DEFER_CLEANUP(struct s2n_client_hello *client_hello = NULL,
                    s2n_client_hello_free);
            EXPECT_OK(s2n_client_hello_from_source(&client_hello, server,
                    client_hello_bytes, sizeof(client_hello_bytes), source));

            uint32_t output_size = 0;
            EXPECT_SUCCESS(s2n_client_hello_get_fingerprint_string(client_hello,
                    S2N_FINGERPRINT_JA3, expected_ja3_size, output_mem, &output_size));
            EXPECT_EQUAL(output_size, expected_ja3_size);
            EXPECT_BYTEARRAY_EQUAL(expected_ja3, output_mem, output_size);
        };
    };

    /* Test: ja3 hash */
    {
        /* Test: basic case */
        {
            DEFER_CLEANUP(struct s2n_connection *client = s2n_connection_new(S2N_CLIENT),
                    s2n_connection_ptr_free);
            EXPECT_NOT_NULL(client);

            DEFER_CLEANUP(struct s2n_connection *server = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            EXPECT_NOT_NULL(server);
            EXPECT_SUCCESS(s2n_connection_set_config(server, config));

            EXPECT_SUCCESS(s2n_client_hello_send(client));
            EXPECT_SUCCESS(s2n_stuffer_copy(&client->handshake.io, &server->handshake.io,
                    s2n_stuffer_data_available(&client->handshake.io)));
            EXPECT_SUCCESS(s2n_client_hello_recv(server));

            struct s2n_client_hello *client_hello = s2n_connection_get_client_hello(server);
            EXPECT_NOT_NULL(client_hello);

            /* Assert reasonable result */
            uint32_t output_size = 0, str_size = 0;
            EXPECT_SUCCESS(s2n_client_hello_get_fingerprint_hash(client_hello,
                    S2N_FINGERPRINT_JA3, MD5_DIGEST_LENGTH, output_mem, &output_size, &str_size));
            EXPECT_TRUE(str_size > MD5_DIGEST_LENGTH);
            EXPECT_EQUAL(output_size, MD5_DIGEST_LENGTH);
            EXPECT_BYTEARRAY_NOT_EQUAL(empty_md5_hash, output_mem, output_size);

            /* Assert same result when given same inputs again */
            uint8_t output_mem_2[MD5_DIGEST_LENGTH] = { 0 };
            uint32_t output_size_2 = 0, str_size_2 = 0;
            EXPECT_SUCCESS(s2n_client_hello_get_fingerprint_hash(client_hello,
                    S2N_FINGERPRINT_JA3, MD5_DIGEST_LENGTH, output_mem_2,
                    &output_size_2, &str_size_2));
            EXPECT_EQUAL(str_size, str_size_2);
            EXPECT_EQUAL(output_size, output_size_2);
            EXPECT_BYTEARRAY_EQUAL(output_mem, output_mem_2, output_size_2);

            /* Assert length for full ja3 string is correct */
            EXPECT_SUCCESS(s2n_client_hello_get_fingerprint_string(client_hello,
                    S2N_FINGERPRINT_JA3, str_size, output_mem, &output_size));
            EXPECT_FAILURE_WITH_ERRNO(
                    s2n_client_hello_get_fingerprint_string(client_hello,
                            S2N_FINGERPRINT_JA3, str_size - 1, output_mem, &output_size),
                    S2N_ERR_INSUFFICIENT_MEM_SIZE);
        };

        /* Test: fails if insufficient memory */
        {
            DEFER_CLEANUP(struct s2n_connection *client = s2n_connection_new(S2N_CLIENT),
                    s2n_connection_ptr_free);
            EXPECT_NOT_NULL(client);

            DEFER_CLEANUP(struct s2n_connection *server = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            EXPECT_NOT_NULL(server);
            EXPECT_SUCCESS(s2n_connection_set_config(server, config));

            EXPECT_SUCCESS(s2n_client_hello_send(client));
            EXPECT_SUCCESS(s2n_stuffer_copy(&client->handshake.io, &server->handshake.io,
                    s2n_stuffer_data_available(&client->handshake.io)));
            EXPECT_SUCCESS(s2n_client_hello_recv(server));

            struct s2n_client_hello *client_hello = s2n_connection_get_client_hello(server);
            EXPECT_NOT_NULL(client_hello);

            uint32_t output_size = 0, str_size = 0;
            for (size_t i = 0; i < MD5_DIGEST_LENGTH; i++) {
                EXPECT_FAILURE_WITH_ERRNO(
                        s2n_client_hello_get_fingerprint_hash(client_hello,
                                S2N_FINGERPRINT_JA3, i, output_mem, &output_size, &str_size),
                        S2N_ERR_INSUFFICIENT_MEM_SIZE);
            }
            EXPECT_EQUAL(output_size, 0);
        };
    };

    /* Test: Known values
     *
     * No definitive source exists for JA3 test vectors.
     * We sample some test values used by other implementations.
     */
    for (size_t i = 0; i < s2n_array_len(sources); i++) {
        s2n_ch_source source = sources[i];

        DEFER_CLEANUP(struct s2n_connection *server = s2n_connection_new(S2N_SERVER),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(server);
        EXPECT_SUCCESS(s2n_connection_set_config(server, config));

        /* Known value from Java implementation:
         * https://github.com/lafaspot/ja3_4java/blob/d605ea2b51c1024eb9056568aac68c2d26011c4f/src/test/resources/openssl-ssl3.bin
         */
        {
            uint8_t raw_client_hello[135] = {
                0x01, 0x00, 0x00, 0x83,
                0x03, 0x00, 0x54, 0x3D, 0xD2, 0xA9, 0xB2, 0xD7, 0x59, 0xF7, 0xC4,
                0xCF, 0x64, 0x30, 0xEB, 0xCC, 0xF7, 0x36, 0x58, 0x9B, 0x78, 0xB8,
                0x9D, 0xB5, 0x0D, 0x59, 0xAF, 0x82, 0xA6, 0xC0, 0xAC, 0xFB, 0xA0,
                0xB1, 0x00, 0x00, 0x5C, 0xC0, 0x14, 0xC0, 0x0A, 0x00, 0x39, 0x00,
                0x38, 0x00, 0x88, 0x00, 0x87, 0xC0, 0x0F, 0xC0, 0x05, 0x00, 0x35,
                0x00, 0x84, 0xC0, 0x12, 0xC0, 0x08, 0x00, 0x16, 0x00, 0x13, 0xC0,
                0x0D, 0xC0, 0x03, 0x00, 0x0A, 0xC0, 0x13, 0xC0, 0x09, 0x00, 0x33,
                0x00, 0x32, 0x00, 0x9A, 0x00, 0x99, 0x00, 0x45, 0x00, 0x44, 0xC0,
                0x0E, 0xC0, 0x04, 0x00, 0x2F, 0x00, 0x96, 0x00, 0x41, 0x00, 0x07,
                0xC0, 0x11, 0xC0, 0x07, 0xC0, 0x0C, 0xC0, 0x02, 0x00, 0x05, 0x00,
                0x04, 0x00, 0x15, 0x00, 0x12, 0x00, 0x09, 0x00, 0x14, 0x00, 0x11,
                0x00, 0x08, 0x00, 0x06, 0x00, 0x03, 0x00, 0xFF, 0x01, 0x00
            };
            const char expected_ja3[] = "768,49172-49162-57-56-136-135-49167-"
                                        "49157-53-132-49170-49160-22-19-49165-49155-"
                                        "10-49171-49161-51-50-154-153-69-68-49166-"
                                        "49156-47-150-65-7-49169-49159-49164-49154-"
                                        "5-4-21-18-9-20-17-8-6-3-255,,,";

            DEFER_CLEANUP(struct s2n_client_hello *client_hello = NULL,
                    s2n_client_hello_free);
            EXPECT_OK(s2n_client_hello_from_source(&client_hello, server,
                    raw_client_hello, sizeof(raw_client_hello), source));

            uint32_t output_size = 0;
            EXPECT_SUCCESS(s2n_client_hello_get_fingerprint_string(client_hello,
                    S2N_FINGERPRINT_JA3, sizeof(output_mem), output_mem, &output_size));
            EXPECT_EQUAL(strlen(expected_ja3), output_size);
            EXPECT_BYTEARRAY_EQUAL(expected_ja3, output_mem, output_size);
        };

        /* Known value from Java implementation:
         * https://github.com/lafaspot/ja3_4java/blob/d605ea2b51c1024eb9056568aac68c2d26011c4f/src/test/resources/openssl-ssl3.bin
         */
        {
            uint8_t raw_client_hello[164] = {
                0x01, 0x00, 0x00, 0xA0,
                0x03, 0x01, 0x54, 0x3D, 0xD2, 0xDD, 0x48, 0xF5, 0x17, 0xCA, 0x9A,
                0x93, 0xB1, 0xE5, 0x99, 0xF0, 0x19, 0xFD, 0xEC, 0xE7, 0x04, 0xA2,
                0x3E, 0x86, 0xC1, 0xDC, 0xAC, 0x58, 0x84, 0x27, 0xAB, 0xBA, 0xDD,
                0xF2, 0x00, 0x00, 0x5C, 0xC0, 0x14, 0xC0, 0x0A, 0x00, 0x39, 0x00,
                0x38, 0x00, 0x88, 0x00, 0x87, 0xC0, 0x0F, 0xC0, 0x05, 0x00, 0x35,
                0x00, 0x84, 0xC0, 0x12, 0xC0, 0x08, 0x00, 0x16, 0x00, 0x13, 0xC0,
                0x0D, 0xC0, 0x03, 0x00, 0x0A, 0xC0, 0x13, 0xC0, 0x09, 0x00, 0x33,
                0x00, 0x32, 0x00, 0x9A, 0x00, 0x99, 0x00, 0x45, 0x00, 0x44, 0xC0,
                0x0E, 0xC0, 0x04, 0x00, 0x2F, 0x00, 0x96, 0x00, 0x41, 0x00, 0x07,
                0xC0, 0x11, 0xC0, 0x07, 0xC0, 0x0C, 0xC0, 0x02, 0x00, 0x05, 0x00,
                0x04, 0x00, 0x15, 0x00, 0x12, 0x00, 0x09, 0x00, 0x14, 0x00, 0x11,
                0x00, 0x08, 0x00, 0x06, 0x00, 0x03, 0x00, 0xFF, 0x01, 0x00, 0x00,
                0x1B, 0x00, 0x0B, 0x00, 0x04, 0x03, 0x00, 0x01, 0x02, 0x00, 0x0A,
                0x00, 0x06, 0x00, 0x04, 0x00, 0x18, 0x00, 0x17, 0x00, 0x23, 0x00,
                0x00, 0x00, 0x0F, 0x00, 0x01, 0x01
            };
            const char expected_ja3[] = "769,49172-49162-57-56-136-135-49167-"
                                        "49157-53-132-49170-49160-22-19-49165-49155-"
                                        "10-49171-49161-51-50-154-153-69-68-49166-"
                                        "49156-47-150-65-7-49169-49159-49164-49154-"
                                        "5-4-21-18-9-20-17-8-6-3-255,11-10-35-15,"
                                        "24-23,0-1-2";

            DEFER_CLEANUP(struct s2n_client_hello *client_hello = NULL,
                    s2n_client_hello_free);
            EXPECT_OK(s2n_client_hello_from_source(&client_hello, server,
                    raw_client_hello, sizeof(raw_client_hello), source));

            uint32_t output_size = 0;
            EXPECT_SUCCESS(s2n_client_hello_get_fingerprint_string(client_hello,
                    S2N_FINGERPRINT_JA3, sizeof(output_mem), output_mem, &output_size));
            EXPECT_EQUAL(strlen(expected_ja3), output_size);
            EXPECT_BYTEARRAY_EQUAL(expected_ja3, output_mem, output_size);
        };

        /* Known value from Java implementation:
         * https://github.com/lafaspot/ja3_4java/blob/d605ea2b51c1024eb9056568aac68c2d26011c4f/src/test/resources/openssl-tls1_1.bin
         */
        {
            uint8_t raw_client_hello[164] = {
                0x01, 0x00, 0x00, 0xA0,
                0x03, 0x02, 0x54, 0x3D, 0xD2, 0xED, 0x90, 0x7E, 0x47, 0xD0, 0x08,
                0x6F, 0x34, 0xBE, 0xE2, 0xC5, 0x2D, 0xD6, 0xCC, 0xD8, 0xDE, 0x63,
                0xBA, 0x93, 0x87, 0xF5, 0xE8, 0x10, 0xB0, 0x9D, 0x9D, 0x49, 0xB3,
                0x80, 0x00, 0x00, 0x5C, 0xC0, 0x14, 0xC0, 0x0A, 0x00, 0x39, 0x00,
                0x38, 0x00, 0x88, 0x00, 0x87, 0xC0, 0x0F, 0xC0, 0x05, 0x00, 0x35,
                0x00, 0x84, 0xC0, 0x12, 0xC0, 0x08, 0x00, 0x16, 0x00, 0x13, 0xC0,
                0x0D, 0xC0, 0x03, 0x00, 0x0A, 0xC0, 0x13, 0xC0, 0x09, 0x00, 0x33,
                0x00, 0x32, 0x00, 0x9A, 0x00, 0x99, 0x00, 0x45, 0x00, 0x44, 0xC0,
                0x0E, 0xC0, 0x04, 0x00, 0x2F, 0x00, 0x96, 0x00, 0x41, 0x00, 0x07,
                0xC0, 0x11, 0xC0, 0x07, 0xC0, 0x0C, 0xC0, 0x02, 0x00, 0x05, 0x00,
                0x04, 0x00, 0x15, 0x00, 0x12, 0x00, 0x09, 0x00, 0x14, 0x00, 0x11,
                0x00, 0x08, 0x00, 0x06, 0x00, 0x03, 0x00, 0xFF, 0x01, 0x00, 0x00,
                0x1B, 0x00, 0x0B, 0x00, 0x04, 0x03, 0x00, 0x01, 0x02, 0x00, 0x0A,
                0x00, 0x06, 0x00, 0x04, 0x00, 0x18, 0x00, 0x17, 0x00, 0x23, 0x00,
                0x00, 0x00, 0x0F, 0x00, 0x01, 0x01
            };
            const char expected_ja3[] = "770,49172-49162-57-56-136-135-49167-"
                                        "49157-53-132-49170-49160-22-19-49165-49155-"
                                        "10-49171-49161-51-50-154-153-69-68-49166-"
                                        "49156-47-150-65-7-49169-49159-49164-49154-"
                                        "5-4-21-18-9-20-17-8-6-3-255,11-10-35-15,"
                                        "24-23,0-1-2";

            DEFER_CLEANUP(struct s2n_client_hello *client_hello = NULL,
                    s2n_client_hello_free);
            EXPECT_OK(s2n_client_hello_from_source(&client_hello, server,
                    raw_client_hello, sizeof(raw_client_hello), source));

            uint32_t output_size = 0;
            EXPECT_SUCCESS(s2n_client_hello_get_fingerprint_string(client_hello,
                    S2N_FINGERPRINT_JA3, sizeof(output_mem), output_mem, &output_size));
            EXPECT_EQUAL(strlen(expected_ja3), output_size);
            EXPECT_BYTEARRAY_EQUAL(expected_ja3, output_mem, output_size);
        };

        /* Known value from Java implementation:
         * https://github.com/lafaspot/ja3_4java/blob/d605ea2b51c1024eb9056568aac68c2d26011c4f/src/test/resources/openssl-tls1_2.bin
         */
        {
            uint8_t raw_client_hello[258] = {
                0x01, 0x00, 0x00, 0xFE,
                0x03, 0x03, 0x54, 0x3D, 0xD3, 0x28, 0x32, 0x83, 0x69, 0x2D, 0x85,
                0xF9, 0x41, 0x6B, 0x5C, 0xCC, 0x65, 0xD2, 0xAA, 0xFC, 0xA4, 0x5C,
                0x65, 0x30, 0xB3, 0xC6, 0xEA, 0xFB, 0xF6, 0xD3, 0x71, 0xB6, 0xA0,
                0x15, 0x00, 0x00, 0x94, 0xC0, 0x30, 0xC0, 0x2C, 0xC0, 0x28, 0xC0,
                0x24, 0xC0, 0x14, 0xC0, 0x0A, 0x00, 0xA3, 0x00, 0x9F, 0x00, 0x6B,
                0x00, 0x6A, 0x00, 0x39, 0x00, 0x38, 0x00, 0x88, 0x00, 0x87, 0xC0,
                0x32, 0xC0, 0x2E, 0xC0, 0x2A, 0xC0, 0x26, 0xC0, 0x0F, 0xC0, 0x05,
                0x00, 0x9D, 0x00, 0x3D, 0x00, 0x35, 0x00, 0x84, 0xC0, 0x12, 0xC0,
                0x08, 0x00, 0x16, 0x00, 0x13, 0xC0, 0x0D, 0xC0, 0x03, 0x00, 0x0A,
                0xC0, 0x2F, 0xC0, 0x2B, 0xC0, 0x27, 0xC0, 0x23, 0xC0, 0x13, 0xC0,
                0x09, 0x00, 0xA2, 0x00, 0x9E, 0x00, 0x67, 0x00, 0x40, 0x00, 0x33,
                0x00, 0x32, 0x00, 0x9A, 0x00, 0x99, 0x00, 0x45, 0x00, 0x44, 0xC0,
                0x31, 0xC0, 0x2D, 0xC0, 0x29, 0xC0, 0x25, 0xC0, 0x0E, 0xC0, 0x04,
                0x00, 0x9C, 0x00, 0x3C, 0x00, 0x2F, 0x00, 0x96, 0x00, 0x41, 0x00,
                0x07, 0xC0, 0x11, 0xC0, 0x07, 0xC0, 0x0C, 0xC0, 0x02, 0x00, 0x05,
                0x00, 0x04, 0x00, 0x15, 0x00, 0x12, 0x00, 0x09, 0x00, 0x14, 0x00,
                0x11, 0x00, 0x08, 0x00, 0x06, 0x00, 0x03, 0x00, 0xFF, 0x01, 0x00,
                0x00, 0x41, 0x00, 0x0B, 0x00, 0x04, 0x03, 0x00, 0x01, 0x02, 0x00,
                0x0A, 0x00, 0x06, 0x00, 0x04, 0x00, 0x18, 0x00, 0x17, 0x00, 0x23,
                0x00, 0x00, 0x00, 0x0D, 0x00, 0x22, 0x00, 0x20, 0x06, 0x01, 0x06,
                0x02, 0x06, 0x03, 0x05, 0x01, 0x05, 0x02, 0x05, 0x03, 0x04, 0x01,
                0x04, 0x02, 0x04, 0x03, 0x03, 0x01, 0x03, 0x02, 0x03, 0x03, 0x02,
                0x01, 0x02, 0x02, 0x02, 0x03, 0x01, 0x01, 0x00, 0x0F, 0x00, 0x01,
                0x01
            };
            const char expected_ja3[] = "771,49200-49196-49192-49188-49172-49162-"
                                        "163-159-107-106-57-56-136-135-49202-49198-"
                                        "49194-49190-49167-49157-157-61-53-132-"
                                        "49170-49160-22-19-49165-49155-10-49199-"
                                        "49195-49191-49187-49171-49161-162-158-103-"
                                        "64-51-50-154-153-69-68-49201-49197-49193-"
                                        "49189-49166-49156-156-60-47-150-65-7-"
                                        "49169-49159-49164-49154-5-4-21-18-9-20-"
                                        "17-8-6-3-255,11-10-35-13-15,24-23,0-1-2";

            DEFER_CLEANUP(struct s2n_client_hello *client_hello = NULL,
                    s2n_client_hello_free);
            EXPECT_OK(s2n_client_hello_from_source(&client_hello, server,
                    raw_client_hello, sizeof(raw_client_hello), source));

            uint32_t output_size = 0;
            EXPECT_SUCCESS(s2n_client_hello_get_fingerprint_string(client_hello,
                    S2N_FINGERPRINT_JA3, sizeof(output_mem), output_mem, &output_size));
            EXPECT_EQUAL(strlen(expected_ja3), output_size);
            EXPECT_BYTEARRAY_EQUAL(expected_ja3, output_mem, output_size);
        };

        /* Known values from Rust implementation:
         * https://github.com/jabedude/ja3-rs/blob/4f2629b86ce3496b4614296f754954806c9c849c/tests/chrome-grease-single.pcap
         */
        {
            uint8_t raw_client_hello[512] = {
                0x01, 0x00, 0x01, 0xFC,
                0x03, 0x03, 0x86, 0xad, 0xa4, 0xcc, 0x19, 0xe7, 0x14, 0x54, 0x54,
                0xfd, 0xe7, 0x37, 0x33, 0xdf, 0x66, 0xcb, 0xf6, 0xef, 0x3e, 0xc0,
                0xa1, 0x54, 0xc6, 0xdd, 0x14, 0x5e, 0xc0, 0x83, 0xac, 0xb9, 0xb4,
                0xe7, 0x20, 0x1c, 0x64, 0xae, 0xa7, 0xa2, 0xc3, 0xe1, 0x8c, 0xd1,
                0x25, 0x02, 0x4d, 0xf7, 0x86, 0x4a, 0xc7, 0x19, 0xd0, 0xc4, 0xbd,
                0xfb, 0x40, 0xc2, 0xef, 0x7f, 0x6d, 0xd3, 0x9a, 0xa7, 0x53, 0xdf,
                0xdd, 0x00, 0x22, 0x1a, 0x1a, 0x13, 0x01, 0x13, 0x02, 0x13, 0x03,
                0xc0, 0x2b, 0xc0, 0x2f, 0xc0, 0x2c, 0xc0, 0x30, 0xcc, 0xa9, 0xcc,
                0xa8, 0xc0, 0x13, 0xc0, 0x14, 0x00, 0x9c, 0x00, 0x9d, 0x00, 0x2f,
                0x00, 0x35, 0x00, 0x0a, 0x01, 0x00, 0x01, 0x91, 0x0a, 0x0a, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x1e, 0x00, 0x00, 0x1b, 0x67,
                0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x61, 0x64, 0x73, 0x2e, 0x67, 0x2e,
                0x64, 0x6f, 0x75, 0x62, 0x6c, 0x65, 0x63, 0x6c, 0x69, 0x63, 0x6b,
                0x2e, 0x6e, 0x65, 0x74, 0x00, 0x17, 0x00, 0x00, 0xff, 0x01, 0x00,
                0x01, 0x00, 0x00, 0x0a, 0x00, 0x0a, 0x00, 0x08, 0x9a, 0x9a, 0x00,
                0x1d, 0x00, 0x17, 0x00, 0x18, 0x00, 0x0b, 0x00, 0x02, 0x01, 0x00,
                0x00, 0x23, 0x00, 0x00, 0x00, 0x10, 0x00, 0x0e, 0x00, 0x0c, 0x02,
                0x68, 0x32, 0x08, 0x68, 0x74, 0x74, 0x70, 0x2f, 0x31, 0x2e, 0x31,
                0x00, 0x05, 0x00, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0d,
                0x00, 0x14, 0x00, 0x12, 0x04, 0x03, 0x08, 0x04, 0x04, 0x01, 0x05,
                0x03, 0x08, 0x05, 0x05, 0x01, 0x08, 0x06, 0x06, 0x01, 0x02, 0x01,
                0x00, 0x12, 0x00, 0x00, 0x00, 0x33, 0x00, 0x2b, 0x00, 0x29, 0x9a,
                0x9a, 0x00, 0x01, 0x00, 0x00, 0x1d, 0x00, 0x20, 0x59, 0x08, 0x6f,
                0x41, 0x9a, 0xa5, 0xaa, 0x1d, 0x81, 0xe3, 0x47, 0xf0, 0x25, 0x5f,
                0x92, 0x07, 0xfc, 0x4b, 0x13, 0x74, 0x51, 0x46, 0x98, 0x08, 0x74,
                0x3b, 0xde, 0x57, 0x86, 0xe8, 0x2c, 0x74, 0x00, 0x2d, 0x00, 0x02,
                0x01, 0x01, 0x00, 0x2b, 0x00, 0x0b, 0x0a, 0xfa, 0xfa, 0x03, 0x04,
                0x03, 0x03, 0x03, 0x02, 0x03, 0x01, 0x00, 0x1b, 0x00, 0x03, 0x02,
                0x00, 0x02, 0xba, 0xba, 0x00, 0x01, 0x00, 0x00, 0x15, 0x00, 0xbd,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00
            };
            const char expected_ja3[] = "771,4865-4866-4867-49195-49199-49196-"
                                        "49200-52393-52392-49171-49172-156-157-47-"
                                        "53-10,0-23-65281-10-11-35-16-5-13-18-51-"
                                        "45-43-27-21,29-23-24,0";
            S2N_BLOB_FROM_HEX(expected_hash, "66918128f1b9b03303d77c6f2eefd128");

            DEFER_CLEANUP(struct s2n_client_hello *client_hello = NULL,
                    s2n_client_hello_free);
            EXPECT_OK(s2n_client_hello_from_source(&client_hello, server,
                    raw_client_hello, sizeof(raw_client_hello), source));

            uint32_t output_size = 0;
            EXPECT_SUCCESS(s2n_client_hello_get_fingerprint_string(client_hello,
                    S2N_FINGERPRINT_JA3, sizeof(output_mem), output_mem, &output_size));
            EXPECT_EQUAL(strlen(expected_ja3), output_size);
            EXPECT_BYTEARRAY_EQUAL(expected_ja3, output_mem, output_size);

            uint32_t str_size = 0;
            EXPECT_SUCCESS(s2n_client_hello_get_fingerprint_hash(client_hello,
                    S2N_FINGERPRINT_JA3, sizeof(output_mem), output_mem, &output_size,
                    &str_size));
            EXPECT_EQUAL(strlen(expected_ja3), str_size);
            EXPECT_EQUAL(expected_hash.size, output_size);
            EXPECT_BYTEARRAY_EQUAL(expected_hash.data, output_mem, output_size);
        };

        /* Known values from Rust implementation:
         * https://github.com/jabedude/ja3-rs/blob/4f2629b86ce3496b4614296f754954806c9c849c/tests/curl-ipv6.pcap
         */
        {
            uint8_t raw_client_hello[512] = {
                0x01, 0x00, 0x01, 0xFC,
                0x03, 0x03, 0x40, 0xc7, 0x8a, 0xef, 0x5c, 0x7f, 0xed, 0x98, 0x4a,
                0x19, 0x8a, 0x03, 0x0b, 0xc0, 0x2d, 0xc0, 0xd6, 0x8f, 0x0b, 0x14,
                0x7d, 0x23, 0x3d, 0x90, 0xb4, 0x2b, 0x4b, 0x28, 0x2c, 0x44, 0x0c,
                0x4d, 0x20, 0xf4, 0x73, 0x04, 0xed, 0x17, 0x42, 0xd6, 0xb5, 0x08,
                0x2e, 0x73, 0x78, 0x71, 0x25, 0x52, 0x5c, 0xea, 0xe7, 0xd7, 0xe5,
                0x7c, 0xfa, 0x27, 0xfe, 0xa3, 0x52, 0x63, 0x7a, 0x27, 0xc3, 0x5d,
                0x58, 0x00, 0x3e, 0x13, 0x02, 0x13, 0x03, 0x13, 0x01, 0xc0, 0x2c,
                0xc0, 0x30, 0x00, 0x9f, 0xcc, 0xa9, 0xcc, 0xa8, 0xcc, 0xaa, 0xc0,
                0x2b, 0xc0, 0x2f, 0x00, 0x9e, 0xc0, 0x24, 0xc0, 0x28, 0x00, 0x6b,
                0xc0, 0x23, 0xc0, 0x27, 0x00, 0x67, 0xc0, 0x0a, 0xc0, 0x14, 0x00,
                0x39, 0xc0, 0x09, 0xc0, 0x13, 0x00, 0x33, 0x00, 0x9d, 0x00, 0x9c,
                0x00, 0x3d, 0x00, 0x3c, 0x00, 0x35, 0x00, 0x2f, 0x00, 0xff, 0x01,
                0x00, 0x01, 0x75, 0x00, 0x00, 0x00, 0x10, 0x00, 0x0e, 0x00, 0x00,
                0x0b, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f,
                0x6d, 0x00, 0x0b, 0x00, 0x04, 0x03, 0x00, 0x01, 0x02, 0x00, 0x0a,
                0x00, 0x0c, 0x00, 0x0a, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x1e, 0x00,
                0x19, 0x00, 0x18, 0x33, 0x74, 0x00, 0x00, 0x00, 0x10, 0x00, 0x0e,
                0x00, 0x0c, 0x02, 0x68, 0x32, 0x08, 0x68, 0x74, 0x74, 0x70, 0x2f,
                0x31, 0x2e, 0x31, 0x00, 0x16, 0x00, 0x00, 0x00, 0x17, 0x00, 0x00,
                0x00, 0x0d, 0x00, 0x30, 0x00, 0x2e, 0x04, 0x03, 0x05, 0x03, 0x06,
                0x03, 0x08, 0x07, 0x08, 0x08, 0x08, 0x09, 0x08, 0x0a, 0x08, 0x0b,
                0x08, 0x04, 0x08, 0x05, 0x08, 0x06, 0x04, 0x01, 0x05, 0x01, 0x06,
                0x01, 0x03, 0x03, 0x02, 0x03, 0x03, 0x01, 0x02, 0x01, 0x03, 0x02,
                0x02, 0x02, 0x04, 0x02, 0x05, 0x02, 0x06, 0x02, 0x00, 0x2b, 0x00,
                0x09, 0x08, 0x03, 0x04, 0x03, 0x03, 0x03, 0x02, 0x03, 0x01, 0x00,
                0x2d, 0x00, 0x02, 0x01, 0x01, 0x00, 0x33, 0x00, 0x26, 0x00, 0x24,
                0x00, 0x1d, 0x00, 0x20, 0x29, 0x90, 0xc2, 0xec, 0x21, 0x68, 0x2c,
                0x5a, 0x7a, 0x5a, 0x46, 0x49, 0x59, 0x42, 0x54, 0x66, 0x02, 0x92,
                0x0c, 0x08, 0x16, 0x59, 0xf6, 0xcc, 0x75, 0xb8, 0x16, 0x53, 0x20,
                0x46, 0x79, 0x23, 0x00, 0x15, 0x00, 0xb6, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00
            };
            const char expected_ja3[] = "771,4866-4867-4865-49196-49200-159-52393-"
                                        "52392-52394-49195-49199-158-49188-49192-"
                                        "107-49187-49191-103-49162-49172-57-49161-"
                                        "49171-51-157-156-61-60-53-47-255,0-11-"
                                        "10-13172-16-22-23-13-43-45-51-21,29-23-"
                                        "30-25-24,0-1-2";
            S2N_BLOB_FROM_HEX(expected_hash, "456523fc94726331a4d5a2e1d40b2cd7");

            DEFER_CLEANUP(struct s2n_client_hello *client_hello = NULL,
                    s2n_client_hello_free);
            EXPECT_OK(s2n_client_hello_from_source(&client_hello, server,
                    raw_client_hello, sizeof(raw_client_hello), source));

            uint32_t output_size = 0;
            EXPECT_SUCCESS(s2n_client_hello_get_fingerprint_string(client_hello,
                    S2N_FINGERPRINT_JA3, sizeof(output_mem), output_mem, &output_size));
            EXPECT_EQUAL(strlen(expected_ja3), output_size);
            EXPECT_BYTEARRAY_EQUAL(expected_ja3, output_mem, output_size);

            uint32_t str_size = 0;
            EXPECT_SUCCESS(s2n_client_hello_get_fingerprint_hash(client_hello,
                    S2N_FINGERPRINT_JA3, sizeof(output_mem), output_mem, &output_size,
                    &str_size));
            EXPECT_EQUAL(strlen(expected_ja3), str_size);
            EXPECT_EQUAL(expected_hash.size, output_size);
            EXPECT_BYTEARRAY_EQUAL(expected_hash.data, output_mem, output_size);
        };

        /* Known values from Rust implementation:
         * https://github.com/jabedude/ja3-rs/blob/4f2629b86ce3496b4614296f754954806c9c849c/tests/test.pcap
         */
        {
            uint8_t raw_client_hello[240] = {
                0x01, 0x00, 0x00, 0xEC,
                0x03, 0x03, 0x90, 0xe8, 0xcc, 0xee, 0xe5, 0x70, 0xa2, 0xa1, 0x2f,
                0x6b, 0x69, 0xd2, 0x66, 0x96, 0x0f, 0xcf, 0x20, 0xd5, 0x32, 0x6e,
                0xc4, 0xb2, 0x8c, 0xc7, 0xbd, 0x0a, 0x06, 0xc2, 0xa5, 0x14, 0xfc,
                0x34, 0x20, 0xaf, 0x72, 0xbf, 0x39, 0x99, 0xfb, 0x20, 0x70, 0xc3,
                0x10, 0x83, 0x0c, 0xee, 0xfb, 0xfa, 0x72, 0xcc, 0x5d, 0xa8, 0x99,
                0xb4, 0xc5, 0x53, 0xd6, 0x3d, 0xa0, 0x53, 0x7a, 0x5c, 0xbc, 0xf5,
                0x0b, 0x00, 0x1e, 0xc0, 0x2b, 0xc0, 0x2f, 0xcc, 0xa9, 0xcc, 0xa8,
                0xc0, 0x2c, 0xc0, 0x30, 0xc0, 0x0a, 0xc0, 0x09, 0xc0, 0x13, 0xc0,
                0x14, 0x00, 0x33, 0x00, 0x39, 0x00, 0x2f, 0x00, 0x35, 0x00, 0x0a,
                0x01, 0x00, 0x00, 0x85, 0x00, 0x00, 0x00, 0x23, 0x00, 0x21, 0x00,
                0x00, 0x1e, 0x69, 0x6e, 0x63, 0x6f, 0x6d, 0x69, 0x6e, 0x67, 0x2e,
                0x74, 0x65, 0x6c, 0x65, 0x6d, 0x65, 0x74, 0x72, 0x79, 0x2e, 0x6d,
                0x6f, 0x7a, 0x69, 0x6c, 0x6c, 0x61, 0x2e, 0x6f, 0x72, 0x67, 0x00,
                0x17, 0x00, 0x00, 0xff, 0x01, 0x00, 0x01, 0x00, 0x00, 0x0a, 0x00,
                0x0a, 0x00, 0x08, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x18, 0x00, 0x19,
                0x00, 0x0b, 0x00, 0x02, 0x01, 0x00, 0x00, 0x23, 0x00, 0x00, 0x00,
                0x10, 0x00, 0x0e, 0x00, 0x0c, 0x02, 0x68, 0x32, 0x08, 0x68, 0x74,
                0x74, 0x70, 0x2f, 0x31, 0x2e, 0x31, 0x00, 0x05, 0x00, 0x05, 0x01,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x0d, 0x00, 0x18, 0x00, 0x16, 0x04,
                0x03, 0x05, 0x03, 0x06, 0x03, 0x08, 0x04, 0x08, 0x05, 0x08, 0x06,
                0x04, 0x01, 0x05, 0x01, 0x06, 0x01, 0x02, 0x03, 0x02, 0x01, 0x00,
                0x1c, 0x00, 0x02, 0x40, 0x00
            };
            const char expected_ja3[] = "771,49195-49199-52393-52392-49196-49200-"
                                        "49162-49161-49171-49172-51-57-47-53-10,0-"
                                        "23-65281-10-11-35-16-5-13-28,29-23-24-25,0";
            S2N_BLOB_FROM_HEX(expected_hash, "839bbe3ed07fed922ded5aaf714d6842");

            DEFER_CLEANUP(struct s2n_client_hello *client_hello = NULL,
                    s2n_client_hello_free);
            EXPECT_OK(s2n_client_hello_from_source(&client_hello, server,
                    raw_client_hello, sizeof(raw_client_hello), source));

            uint32_t output_size = 0;
            EXPECT_SUCCESS(s2n_client_hello_get_fingerprint_string(client_hello,
                    S2N_FINGERPRINT_JA3, sizeof(output_mem), output_mem, &output_size));
            EXPECT_EQUAL(strlen(expected_ja3), output_size);
            EXPECT_BYTEARRAY_EQUAL(expected_ja3, output_mem, output_size);

            uint32_t str_size = 0;
            EXPECT_SUCCESS(s2n_client_hello_get_fingerprint_hash(client_hello,
                    S2N_FINGERPRINT_JA3, sizeof(output_mem), output_mem, &output_size,
                    &str_size));
            EXPECT_EQUAL(strlen(expected_ja3), str_size);
            EXPECT_EQUAL(expected_hash.size, output_size);
            EXPECT_BYTEARRAY_EQUAL(expected_hash.data, output_mem, output_size);
        };

        /* Known values from Rust implementation:
         * https://github.com/jabedude/ja3-rs/blob/4f2629b86ce3496b4614296f754954806c9c849c/tests/ncat-port-4450.pcap
         */
        {
            uint8_t raw_client_hello[512] = {
                0x01, 0x00, 0x01, 0xFC,
                0x03, 0x03, 0xf4, 0x0f, 0xfd, 0xee, 0xc7, 0x27, 0xc2, 0x1e, 0x32,
                0x70, 0x5f, 0x85, 0x25, 0xa6, 0xbb, 0x6c, 0xca, 0x4b, 0x6c, 0xbe,
                0x01, 0x66, 0x32, 0x66, 0x76, 0x4b, 0x67, 0x74, 0x3b, 0x91, 0xbd,
                0xb2, 0x20, 0x83, 0xd4, 0x9e, 0x77, 0xaf, 0xc1, 0x5a, 0x63, 0x35,
                0xba, 0x2f, 0xe9, 0x76, 0xbe, 0x9a, 0x42, 0x6b, 0x2e, 0xb5, 0x58,
                0x23, 0x84, 0x2a, 0x99, 0x2b, 0x37, 0x88, 0xd1, 0xf7, 0x9d, 0xd6,
                0x20, 0x00, 0x9c, 0x13, 0x02, 0x13, 0x03, 0x13, 0x01, 0xc0, 0x2c,
                0xc0, 0x30, 0x00, 0xa3, 0x00, 0x9f, 0xcc, 0xa9, 0xcc, 0xa8, 0xcc,
                0xaa, 0xc0, 0xaf, 0xc0, 0xad, 0xc0, 0xa3, 0xc0, 0x9f, 0xc0, 0x5d,
                0xc0, 0x61, 0xc0, 0x57, 0xc0, 0x53, 0xc0, 0x24, 0xc0, 0x28, 0x00,
                0x6b, 0x00, 0x6a, 0xc0, 0x73, 0xc0, 0x77, 0x00, 0xc4, 0x00, 0xc3,
                0xc0, 0x0a, 0xc0, 0x14, 0x00, 0x39, 0x00, 0x38, 0x00, 0x88, 0x00,
                0x87, 0x00, 0x9d, 0xc0, 0xa1, 0xc0, 0x9d, 0xc0, 0x51, 0x00, 0x3d,
                0x00, 0xc0, 0x00, 0x35, 0x00, 0x84, 0xc0, 0x2b, 0xc0, 0x2f, 0x00,
                0xa2, 0x00, 0x9e, 0xc0, 0xae, 0xc0, 0xac, 0xc0, 0xa2, 0xc0, 0x9e,
                0xc0, 0x5c, 0xc0, 0x60, 0xc0, 0x56, 0xc0, 0x52, 0xc0, 0x23, 0xc0,
                0x27, 0x00, 0x67, 0x00, 0x40, 0xc0, 0x72, 0xc0, 0x76, 0x00, 0xbe,
                0x00, 0xbd, 0xc0, 0x09, 0xc0, 0x13, 0x00, 0x33, 0x00, 0x32, 0x00,
                0x9a, 0x00, 0x99, 0x00, 0x45, 0x00, 0x44, 0x00, 0x9c, 0xc0, 0xa0,
                0xc0, 0x9c, 0xc0, 0x50, 0x00, 0x3c, 0x00, 0xba, 0x00, 0x2f, 0x00,
                0x96, 0x00, 0x41, 0x00, 0xff, 0x01, 0x00, 0x01, 0x17, 0x00, 0x00,
                0x00, 0x0e, 0x00, 0x0c, 0x00, 0x00, 0x09, 0x31, 0x32, 0x37, 0x2e,
                0x30, 0x2e, 0x30, 0x2e, 0x31, 0x00, 0x0b, 0x00, 0x04, 0x03, 0x00,
                0x01, 0x02, 0x00, 0x0a, 0x00, 0x0c, 0x00, 0x0a, 0x00, 0x1d, 0x00,
                0x17, 0x00, 0x1e, 0x00, 0x19, 0x00, 0x18, 0x00, 0x23, 0x00, 0x00,
                0x00, 0x16, 0x00, 0x00, 0x00, 0x17, 0x00, 0x00, 0x00, 0x0d, 0x00,
                0x30, 0x00, 0x2e, 0x04, 0x03, 0x05, 0x03, 0x06, 0x03, 0x08, 0x07,
                0x08, 0x08, 0x08, 0x09, 0x08, 0x0a, 0x08, 0x0b, 0x08, 0x04, 0x08,
                0x05, 0x08, 0x06, 0x04, 0x01, 0x05, 0x01, 0x06, 0x01, 0x03, 0x03,
                0x02, 0x03, 0x03, 0x01, 0x02, 0x01, 0x03, 0x02, 0x02, 0x02, 0x04,
                0x02, 0x05, 0x02, 0x06, 0x02, 0x00, 0x2b, 0x00, 0x09, 0x08, 0x03,
                0x04, 0x03, 0x03, 0x03, 0x02, 0x03, 0x01, 0x00, 0x2d, 0x00, 0x02,
                0x01, 0x01, 0x00, 0x33, 0x00, 0x26, 0x00, 0x24, 0x00, 0x1d, 0x00,
                0x20, 0x29, 0x61, 0x96, 0xc4, 0x0c, 0x16, 0x7c, 0xde, 0x20, 0x01,
                0x86, 0x32, 0xdf, 0x84, 0x2f, 0x67, 0x2f, 0x3f, 0x64, 0x17, 0xc0,
                0x2e, 0xa2, 0xb2, 0x9e, 0xfc, 0xa8, 0xb0, 0xc5, 0x71, 0x6e, 0x7d,
                0x00, 0x15, 0x00, 0x6c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00
            };
            const char expected_ja3[] = "771,4866-4867-4865-49196-49200-163-159-"
                                        "52393-52392-52394-49327-49325-49315-"
                                        "49311-49245-49249-49239-49235-49188-49192-"
                                        "107-106-49267-49271-196-195-49162-49172-"
                                        "57-56-136-135-157-49313-49309-49233-61-"
                                        "192-53-132-49195-49199-162-158-49326-"
                                        "49324-49314-49310-49244-49248-49238-49234-"
                                        "49187-49191-103-64-49266-49270-190-189-"
                                        "49161-49171-51-50-154-153-69-68-156-49312-"
                                        "49308-49232-60-186-47-150-65-255,0-11-"
                                        "10-35-22-23-13-43-45-51-21,29-23-30-25-"
                                        "24,0-1-2";
            S2N_BLOB_FROM_HEX(expected_hash, "10a6b69a81bac09072a536ce9d35dd43");

            DEFER_CLEANUP(struct s2n_client_hello *client_hello = NULL,
                    s2n_client_hello_free);
            EXPECT_OK(s2n_client_hello_from_source(&client_hello, server,
                    raw_client_hello, sizeof(raw_client_hello), source));

            uint32_t output_size = 0;
            EXPECT_SUCCESS(s2n_client_hello_get_fingerprint_string(client_hello,
                    S2N_FINGERPRINT_JA3, sizeof(output_mem), output_mem, &output_size));
            EXPECT_EQUAL(strlen(expected_ja3), output_size);
            EXPECT_BYTEARRAY_EQUAL(expected_ja3, output_mem, output_size);

            uint32_t str_size = 0;
            EXPECT_SUCCESS(s2n_client_hello_get_fingerprint_hash(client_hello,
                    S2N_FINGERPRINT_JA3, sizeof(output_mem), output_mem, &output_size,
                    &str_size));
            EXPECT_EQUAL(strlen(expected_ja3), str_size);
            EXPECT_EQUAL(expected_hash.size, output_size);
            EXPECT_BYTEARRAY_EQUAL(expected_hash.data, output_mem, output_size);
        };
    };

    END_TEST();
}
