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
#include "tls/extensions/s2n_ec_point_format.h"
#include "tls/s2n_cipher_suites.h"
#include "tls/s2n_resume.h"

int main(int argc, char **argv)
{
    BEGIN_TEST();
    EXPECT_SUCCESS(s2n_disable_tls13_in_test());

    struct s2n_config *config;
    EXPECT_NOT_NULL(config = s2n_config_new());

    /* Test server should_send */
    {
        struct s2n_connection *conn;
        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));

        /* Do not send for null connection */
        EXPECT_FALSE(s2n_server_ec_point_format_extension.should_send(NULL));

        /* Do not send for connection without chosen cipher */
        conn->secure->cipher_suite = NULL;
        EXPECT_FALSE(s2n_server_ec_point_format_extension.should_send(conn));

        /* Do not send for connection without ec kex */
        conn->secure->cipher_suite = &s2n_rsa_with_aes_128_cbc_sha;
        EXPECT_FALSE(s2n_server_ec_point_format_extension.should_send(conn));
        conn->secure->cipher_suite = &s2n_dhe_rsa_with_chacha20_poly1305_sha256;
        EXPECT_FALSE(s2n_server_ec_point_format_extension.should_send(conn));

        /* Do send for connection with ec kex */
        conn->secure->cipher_suite = &s2n_ecdhe_ecdsa_with_aes_128_cbc_sha;
        EXPECT_TRUE(s2n_server_ec_point_format_extension.should_send(conn));

        /* Do send for connection with hybrid ec kex */
        conn->secure->cipher_suite = &s2n_ecdhe_kyber_rsa_with_aes_256_gcm_sha384;
        EXPECT_TRUE(s2n_server_ec_point_format_extension.should_send(conn));

        EXPECT_SUCCESS(s2n_connection_free(conn));
    };

    /* Test send */
    {
        struct s2n_connection *conn;
        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));
        EXPECT_SUCCESS(s2n_connection_set_config(conn, config));

        struct s2n_stuffer stuffer = { 0 };
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&stuffer, 0));

        EXPECT_SUCCESS(s2n_client_ec_point_format_extension.send(conn, &stuffer));

        uint8_t length;
        EXPECT_SUCCESS(s2n_stuffer_read_uint8(&stuffer, &length));
        EXPECT_EQUAL(length, s2n_stuffer_data_available(&stuffer));

        uint8_t point_format;
        EXPECT_SUCCESS(s2n_stuffer_read_uint8(&stuffer, &point_format));
        EXPECT_EQUAL(point_format, TLS_EC_POINT_FORMAT_UNCOMPRESSED);

        EXPECT_EQUAL(s2n_stuffer_data_available(&stuffer), 0);

        EXPECT_SUCCESS(s2n_stuffer_free(&stuffer));
        EXPECT_SUCCESS(s2n_connection_free(conn));
    };

    /* Test recv */
    {
        struct s2n_connection *conn;
        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));
        EXPECT_SUCCESS(s2n_connection_set_config(conn, config));

        struct s2n_stuffer stuffer = { 0 };
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&stuffer, 0));

        EXPECT_SUCCESS(s2n_client_ec_point_format_extension.send(conn, &stuffer));

        EXPECT_FALSE(conn->ec_point_formats);
        EXPECT_SUCCESS(s2n_client_ec_point_format_extension.recv(conn, &stuffer));
        EXPECT_TRUE(conn->ec_point_formats);

        EXPECT_SUCCESS(s2n_stuffer_free(&stuffer));
        EXPECT_SUCCESS(s2n_connection_free(conn));
    };

    EXPECT_SUCCESS(s2n_config_free(config));

    END_TEST();
    return 0;
}
