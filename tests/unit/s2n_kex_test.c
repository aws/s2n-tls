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

#include "tls/s2n_kex.h"

#include "tests/s2n_test.h"

int main(int argc, char **argv)
{
    BEGIN_TEST();
    EXPECT_SUCCESS(s2n_disable_tls13_in_test());

    /* Test safety checks */
    {
        struct s2n_connection conn = { 0 };
        struct s2n_blob blob = { 0 };
        struct s2n_kex_raw_server_data test_raw_server_data = { 0 };
        struct s2n_cipher_suite test_cipher = s2n_ecdhe_rsa_with_aes_256_cbc_sha;
        struct s2n_cipher_suite test_cipher_with_null_kex = test_cipher;
        test_cipher_with_null_kex.key_exchange_alg = NULL;

        /* Null cipher suite kex - possible with tls1.3 cipher suites */
        EXPECT_ERROR(s2n_configure_kex(NULL, &conn));
        EXPECT_ERROR(s2n_configure_kex(&test_cipher_with_null_kex, NULL));

        /* Null kex -- possible with tls1.3 cipher suites */
        bool is_ephemeral = false;
        EXPECT_ERROR(s2n_kex_is_ephemeral(NULL, &is_ephemeral));
        EXPECT_ERROR(s2n_kex_is_ephemeral(&s2n_rsa, NULL));
        EXPECT_ERROR(s2n_kex_server_key_recv_parse_data(NULL, &conn, &test_raw_server_data));
        EXPECT_ERROR(s2n_kex_server_key_recv_read_data(NULL, &conn, &blob, &test_raw_server_data));
        EXPECT_ERROR(s2n_kex_server_key_send(NULL, &conn, &blob));
        EXPECT_ERROR(s2n_kex_client_key_recv(NULL, &conn, &blob));
        EXPECT_ERROR(s2n_kex_client_key_send(NULL, &conn, &blob));
        EXPECT_ERROR(s2n_kex_tls_prf(NULL, &conn, &blob));
    };

    /* Test s2n_kex_includes */
    {
        /* True if same kex */
        EXPECT_TRUE(s2n_kex_includes(NULL, NULL));
        EXPECT_TRUE(s2n_kex_includes(&s2n_rsa, &s2n_rsa));
        EXPECT_TRUE(s2n_kex_includes(&s2n_hybrid_ecdhe_kem, &s2n_hybrid_ecdhe_kem));

        /* False if different kex */
        EXPECT_FALSE(s2n_kex_includes(&s2n_rsa, &s2n_dhe));
        EXPECT_FALSE(s2n_kex_includes(&s2n_kem, &s2n_ecdhe));

        /* True if hybrid that contains */
        EXPECT_TRUE(s2n_kex_includes(&s2n_hybrid_ecdhe_kem, &s2n_ecdhe));
        EXPECT_TRUE(s2n_kex_includes(&s2n_hybrid_ecdhe_kem, &s2n_kem));

        /* False if hybrid "contains" relationship reversed */
        EXPECT_FALSE(s2n_kex_includes(&s2n_ecdhe, &s2n_hybrid_ecdhe_kem));
        EXPECT_FALSE(s2n_kex_includes(&s2n_kem, &s2n_hybrid_ecdhe_kem));

        /* False if hybrid that does not contain */
        EXPECT_FALSE(s2n_kex_includes(&s2n_hybrid_ecdhe_kem, &s2n_rsa));
        EXPECT_FALSE(s2n_kex_includes(&s2n_hybrid_ecdhe_kem, &s2n_dhe));

        /* False if one kex null */
        EXPECT_FALSE(s2n_kex_includes(&s2n_rsa, NULL));
        EXPECT_FALSE(s2n_kex_includes(NULL, &s2n_rsa));
    };

    END_TEST();
}
