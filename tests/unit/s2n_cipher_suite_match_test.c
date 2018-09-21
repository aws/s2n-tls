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

#include <string.h>

#include "tls/s2n_cipher_suites.h"
#include "tls/s2n_connection.h"

int main(int argc, char **argv)
{
    BEGIN_TEST();

    EXPECT_SUCCESS(setenv("S2N_ENABLE_CLIENT_MODE", "1", 0));

    {
        struct s2n_connection *conn;
        uint8_t wire[2];
        int count;
        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));

        count = 0;
        for (int i = 0; i < 0xffff; i++) {
            wire[0] = (i >> 8);
            wire[1] = i & 0xff;

            if (s2n_set_cipher_as_client(conn, wire) == 0) {
                count++;
            }
        }

        /* We should have exactly 31 cipher suites */
        EXPECT_EQUAL(count, 31);

        EXPECT_SUCCESS(s2n_connection_free(conn));
    }

    /* Test server cipher selection and scsv detection */
    {
        struct s2n_connection *conn;
        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));

        uint8_t wire_ciphers[] = {
            TLS_RSA_WITH_RC4_128_MD5,
            TLS_RSA_WITH_RC4_128_SHA,
            TLS_RSA_WITH_3DES_EDE_CBC_SHA,
            TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA,
            TLS_RSA_WITH_AES_128_CBC_SHA,
            TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
            TLS_RSA_WITH_AES_256_CBC_SHA,
            TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
            TLS_RSA_WITH_AES_128_CBC_SHA256,
            TLS_RSA_WITH_AES_256_CBC_SHA256,
            TLS_DHE_RSA_WITH_AES_128_CBC_SHA256,
            TLS_DHE_RSA_WITH_AES_256_CBC_SHA256,
            TLS_RSA_WITH_AES_128_GCM_SHA256,
            TLS_RSA_WITH_AES_256_GCM_SHA384,
            TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
            TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
            TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
            TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
            TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
            TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
            TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        };

        uint8_t wire_ciphers_fallback[] = {
            TLS_RSA_WITH_RC4_128_MD5,
            TLS_RSA_WITH_RC4_128_SHA,
            TLS_RSA_WITH_3DES_EDE_CBC_SHA,
            TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA,
            TLS_RSA_WITH_AES_128_CBC_SHA,
            TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
            TLS_RSA_WITH_AES_256_CBC_SHA,
            TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
            TLS_RSA_WITH_AES_128_CBC_SHA256,
            TLS_RSA_WITH_AES_256_CBC_SHA256,
            TLS_DHE_RSA_WITH_AES_128_CBC_SHA256,
            TLS_DHE_RSA_WITH_AES_256_CBC_SHA256,
            TLS_RSA_WITH_AES_128_GCM_SHA256,
            TLS_RSA_WITH_AES_256_GCM_SHA384,
            TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
            TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
            TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
            TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
            TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
            TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
            TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
            TLS_FALLBACK_SCSV, /* At the end to verify it isn't missed */
        };

        uint8_t wire_ciphers_renegotiation[] = {
            TLS_RSA_WITH_RC4_128_MD5,
            TLS_RSA_WITH_RC4_128_SHA,
            TLS_RSA_WITH_3DES_EDE_CBC_SHA,
            TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA,
            TLS_RSA_WITH_AES_128_CBC_SHA,
            TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
            TLS_RSA_WITH_AES_256_CBC_SHA,
            TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
            TLS_RSA_WITH_AES_128_CBC_SHA256,
            TLS_RSA_WITH_AES_256_CBC_SHA256,
            TLS_DHE_RSA_WITH_AES_128_CBC_SHA256,
            TLS_DHE_RSA_WITH_AES_256_CBC_SHA256,
            TLS_RSA_WITH_AES_128_GCM_SHA256,
            TLS_RSA_WITH_AES_256_GCM_SHA384,
            TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
            TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
            TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
            TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
            TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
            TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
            TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
            TLS_EMPTY_RENEGOTIATION_INFO_SCSV, /* At the end to verify it isn't missed */
        };

        const uint8_t cipher_count = sizeof(wire_ciphers) / S2N_TLS_CIPHER_SUITE_LEN;
        EXPECT_SUCCESS(s2n_set_cipher_as_tls_server(conn, wire_ciphers, cipher_count));
        EXPECT_EQUAL(conn->secure_renegotiation, 0);
        conn->actual_protocol_version = S2N_TLS10;
        EXPECT_EQUAL(1, s2n_connection_is_valid_for_cipher_preferences(conn, "test_all")); 
        EXPECT_EQUAL(0, s2n_connection_is_valid_for_cipher_preferences(conn, "null"));
        EXPECT_SUCCESS(s2n_connection_wipe(conn));

        const uint8_t cipher_count_renegotiation = sizeof(wire_ciphers_renegotiation) / S2N_TLS_CIPHER_SUITE_LEN;
        EXPECT_SUCCESS(s2n_set_cipher_as_tls_server(conn, wire_ciphers_renegotiation, cipher_count_renegotiation));
        EXPECT_EQUAL(conn->secure_renegotiation, 1);
        conn->actual_protocol_version = S2N_TLS12;
        EXPECT_EQUAL(1, s2n_connection_is_valid_for_cipher_preferences(conn, "test_all")); 
        EXPECT_EQUAL(-1, s2n_connection_is_valid_for_cipher_preferences(conn, "not_exist"));
        EXPECT_SUCCESS(s2n_connection_wipe(conn));

        const uint8_t cipher_count_fallback = sizeof(wire_ciphers_fallback) / S2N_TLS_CIPHER_SUITE_LEN;
        /* Simulate a TLSv11 client to trigger the fallback error */
        conn->client_protocol_version = S2N_TLS11;
        EXPECT_FAILURE(s2n_set_cipher_as_tls_server(conn, wire_ciphers_fallback, cipher_count_fallback));
        EXPECT_EQUAL(conn->secure_renegotiation, 0);
        conn->actual_protocol_version = S2N_TLS11;
        EXPECT_EQUAL(1, s2n_connection_is_valid_for_cipher_preferences(conn, "null"));
        EXPECT_EQUAL(0, s2n_connection_is_valid_for_cipher_preferences(conn, "CloudFront-TLS-1-2-2018"));
        EXPECT_SUCCESS(s2n_connection_wipe(conn));

        EXPECT_SUCCESS(s2n_connection_free(conn));
    }

    END_TEST();
}
