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

#include "tls/s2n_tls.h"
#include "tls/s2n_tls13.h"
#include "tls/s2n_config.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_client_extensions.h"
#include "tls/s2n_cipher_suites.h"

static uint8_t tls13_extensions[] = { TLS_EXTENSION_SUPPORTED_VERSIONS, TLS_EXTENSION_KEY_SHARE };

int main(int argc, char **argv)
{
    BEGIN_TEST();

    /* TLS 1.3 is not enabled by default */
    EXPECT_FALSE(s2n_is_tls13_enabled());

    /* Client does not use TLS 1.3 by default */
    {
        struct s2n_connection *conn;
        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));

        EXPECT_NOT_EQUAL(conn->client_protocol_version, S2N_TLS13);

        EXPECT_SUCCESS(s2n_connection_free(conn));
    }

    /* Server does not use TLS 1.3 by default */
    {
        struct s2n_connection *conn;
        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));

        EXPECT_NOT_EQUAL(conn->server_protocol_version, S2N_TLS13);

        EXPECT_SUCCESS(s2n_connection_free(conn));
    }

    /* Server does not parse new TLS 1.3 extensions by default */
    {
        struct s2n_connection *server_conn;
        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));

        struct s2n_stuffer extension_data;
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&extension_data, 0));
        EXPECT_SUCCESS(s2n_stuffer_write_str(&extension_data, "bad extension"));

        uint8_t original_data_size = s2n_stuffer_data_available(&extension_data);

        struct s2n_array *extensions = s2n_array_new(sizeof(struct s2n_client_hello_parsed_extension));
        for (int i=0; i < s2n_array_len(tls13_extensions); i++) {
            struct s2n_client_hello_parsed_extension *extension;
            EXPECT_NOT_NULL(extension = s2n_array_pushback(extensions));

            extension->extension = extension_data.blob;
            extension->extension_type = tls13_extensions[i];
        }

        EXPECT_SUCCESS(s2n_client_extensions_recv(server_conn, extensions));
        /* None of the extensions parsed any data */
        EXPECT_EQUAL(original_data_size, s2n_stuffer_data_available(&extension_data));

        EXPECT_SUCCESS(s2n_connection_free(server_conn));
        EXPECT_SUCCESS(s2n_stuffer_free(&extension_data));
        EXPECT_SUCCESS(s2n_array_free(extensions));
    }

    EXPECT_SUCCESS(s2n_enable_tls13());
    EXPECT_TRUE(s2n_is_tls13_enabled());

    /* Re-enabling has no effect */
    EXPECT_SUCCESS(s2n_enable_tls13());
    EXPECT_TRUE(s2n_is_tls13_enabled());

    /* Client does use TLS 1.3 if enabled */
    {
        struct s2n_connection *conn;
        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));

        EXPECT_EQUAL(conn->client_protocol_version, S2N_TLS13);

        EXPECT_SUCCESS(s2n_connection_free(conn));
    }

    /* Server does use TLS 1.3 if enabled */
    {
        struct s2n_connection *conn;
        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));

        EXPECT_EQUAL(conn->server_protocol_version, S2N_TLS13);

        EXPECT_SUCCESS(s2n_connection_free(conn));
    }

    /* Server does parse new TLS 1.3 extensions if enabled */
    {
        uint8_t new_extensions[] = { TLS_EXTENSION_SUPPORTED_VERSIONS, TLS_EXTENSION_KEY_SHARE };

        struct s2n_connection *server_conn;
        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));

        struct s2n_stuffer extension_data;
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&extension_data, 0));

        struct s2n_array *extensions = s2n_array_new(sizeof(struct s2n_client_hello_parsed_extension));
        struct s2n_client_hello_parsed_extension *extension;
        EXPECT_NOT_NULL(extension = s2n_array_pushback(extensions));

        /* Protocol version is required for key share extension parsing */
        server_conn->actual_protocol_version = S2N_TLS13;
        for (int i = 0; i < s2n_array_len(new_extensions); i++) {
            EXPECT_SUCCESS(s2n_stuffer_wipe(&extension_data));
            EXPECT_SUCCESS(s2n_stuffer_write_str(&extension_data, "bad extension"));

            extension->extension_type = new_extensions[i];

            /* We can't just take a stuffer blob as its size is all allocated memory, not all written data,
             * so do a stuffer read here. */
            extension->extension.size = s2n_stuffer_data_available(&extension_data);
            extension->extension.data = s2n_stuffer_raw_read(&extension_data, extension->extension.size);
            EXPECT_NOT_NULL(extension->extension.data);

            /* We're not passing in well-formed extensions, so if they are parsed then they should fail */
            EXPECT_FAILURE(s2n_client_extensions_recv(server_conn, extensions));

            /* Zero out the blob to avoid dangling pointer */
            EXPECT_SUCCESS(s2n_blob_zero(&extension->extension));
        }

        EXPECT_SUCCESS(s2n_connection_free(server_conn));
        EXPECT_SUCCESS(s2n_stuffer_free(&extension_data));
        EXPECT_SUCCESS(s2n_array_free(extensions));
    }

    EXPECT_SUCCESS(s2n_disable_tls13());
    EXPECT_FALSE(s2n_is_tls13_enabled());

    /* Re-disabling has no effect */
    EXPECT_SUCCESS(s2n_disable_tls13());
    EXPECT_FALSE(s2n_is_tls13_enabled());

    /* TLS 1.3 can't be enabled outside of unit tests */
    EXPECT_SUCCESS(s2n_in_unit_test_set(false));
    EXPECT_FAILURE_WITH_ERRNO(s2n_enable_tls13(), S2N_ERR_NOT_IN_UNIT_TEST);

    /* Test s2n_is_valid_tls13_cipher() */
    {
        uint8_t value[2] = { 0x13, 0x01 };
        EXPECT_TRUE(s2n_is_valid_tls13_cipher(value));
        value[0] = 0x13; value[1] = 0x02;
        EXPECT_TRUE(s2n_is_valid_tls13_cipher(value));
        value[0] = 0x13; value[1] = 0x03;
        EXPECT_TRUE(s2n_is_valid_tls13_cipher(value));
        value[0] = 0x13; value[1] = 0x04;
        EXPECT_TRUE(s2n_is_valid_tls13_cipher(value));
        value[0] = 0x13; value[1] = 0x05;
        EXPECT_TRUE(s2n_is_valid_tls13_cipher(value));
        value[0] = 0x13; value[1] = 0x06;
        EXPECT_FALSE(s2n_is_valid_tls13_cipher(value));
        value[0] = 0x13; value[1] = 0x00;
        EXPECT_FALSE(s2n_is_valid_tls13_cipher(value));
        value[0] = 0x12; value[1] = 0x01;
        EXPECT_FALSE(s2n_is_valid_tls13_cipher(value));

        EXPECT_FALSE(s2n_is_valid_tls13_cipher(s2n_dhe_rsa_with_3des_ede_cbc_sha.iana_value));
        EXPECT_TRUE(s2n_is_valid_tls13_cipher(s2n_tls13_aes_128_gcm_sha256.iana_value));
        EXPECT_TRUE(s2n_is_valid_tls13_cipher(s2n_tls13_aes_256_gcm_sha384.iana_value));
        EXPECT_TRUE(s2n_is_valid_tls13_cipher(s2n_tls13_chacha20_poly1305_sha256.iana_value));
    }

    END_TEST();
    return 0;
}
