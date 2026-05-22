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

#include <openssl/bn.h>
#include <openssl/dh.h>

#include "crypto/s2n_dhe.h"
#include "tests/s2n_test.h"

/* Test DH parameters (2048-bit prime from RFC 3526) */
static const char dhparams_pem[] =
        "-----BEGIN DH PARAMETERS-----\n"
        "MIIBCAKCAQEA///////////JD9qiIWjCNMTGYouA3BzRKQJOCIpnzHQCC76mOxOb\n"
        "IlFKCHmONATd75UZs806QxswKwpt8l8UN0/hNW1tUcJF5IW1dmJefsb0TELppjft\n"
        "awv/XLb0Brft7jhr+1qJn6WunyQRfEsf5kkoZlHs5Fs9wgB8uKFjvwWY2kg2HFXT\n"
        "mmkWP6j9JM9fg2VdI9yjrZYcYvNWIIVSu57VKQdwlpZtZww1Tkq8mATxdGwIyhgh\n"
        "fDKQXkYuNs474553LBgOhgObJ4Oi7Aeij7XFXfBvTFLJ3ivL9pVYFxg5lUl86pVq\n"
        "5RXSJhiY+gUQFXKOWoqsqmj//////////wIBAg==\n"
        "-----END DH PARAMETERS-----\n";

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

    /* DHE Test: Client sends Yc_length larger than server DH params size */
    {
        struct s2n_dh_params server_dh_params = { 0 };
        struct s2n_blob shared_key = { 0 };
        struct s2n_stuffer Yc_in = { 0 };
        struct s2n_stuffer dhparams_in = { 0 };
        struct s2n_stuffer dhparams_out = { 0 };

        /* Setup server DH params (2048-bit = 256 bytes) */
        EXPECT_SUCCESS(s2n_stuffer_alloc(&dhparams_in, sizeof(dhparams_pem)));
        EXPECT_SUCCESS(s2n_stuffer_alloc(&dhparams_out, sizeof(dhparams_pem)));
        EXPECT_SUCCESS(s2n_stuffer_write_bytes(&dhparams_in, (uint8_t *) dhparams_pem, sizeof(dhparams_pem)));
        EXPECT_SUCCESS(s2n_stuffer_dhparams_from_pem(&dhparams_in, &dhparams_out));

        uint32_t available_size = s2n_stuffer_data_available(&dhparams_out);
        struct s2n_blob dhparams_blob = { 0 };
        EXPECT_SUCCESS(s2n_blob_init(&dhparams_blob, s2n_stuffer_raw_read(&dhparams_out, available_size), available_size));

        /* s2n_pkcs3_to_dh_params calls DH_check() which has different behavior
         * in some libcrypto versions (e.g. OpenSSL 1.0.2, AWS-LC FIPS 2022).
         * Skip this test if DH param validation fails. */
        if (s2n_pkcs3_to_dh_params(&server_dh_params, &dhparams_blob) == S2N_SUCCESS) {
            EXPECT_SUCCESS(s2n_dh_generate_ephemeral_key(&server_dh_params));
            int server_dh_size = DH_size(server_dh_params.dh);
            EXPECT_EQUAL(server_dh_size, 256); /* 2048 bits = 256 bytes */

            /* Allocate stuffer for client-controlled input */
            EXPECT_SUCCESS(s2n_stuffer_alloc(&Yc_in, 1024));
            /* Client sends Yc_length = 512 (larger than server_dh_size = 256) */
            uint16_t malicious_Yc_length = 512;
            EXPECT_SUCCESS(s2n_stuffer_write_uint16(&Yc_in, malicious_Yc_length));

            /* Fill with dummy data to satisfy stuffer bounds check */
            for (int i = 0; i < malicious_Yc_length; i++) {
                EXPECT_SUCCESS(s2n_stuffer_write_uint8(&Yc_in, 0xFF));
            }
            /* Verify the oversized input: Yc_length (512) > server_dh_size (256) */
            EXPECT_TRUE(malicious_Yc_length > server_dh_size);

            /* This function should fail due to the bound check */
            EXPECT_FAILURE_WITH_ERRNO(s2n_dh_compute_shared_secret_as_server(&server_dh_params, &Yc_in, &shared_key),
                    S2N_ERR_DH_SHARED_SECRET);

            /* Cleanup */
            EXPECT_SUCCESS(s2n_free(&shared_key));
            EXPECT_SUCCESS(s2n_stuffer_free(&Yc_in));
            EXPECT_SUCCESS(s2n_dh_params_free(&server_dh_params));
        }

        EXPECT_SUCCESS(s2n_stuffer_free(&dhparams_in));
        EXPECT_SUCCESS(s2n_stuffer_free(&dhparams_out));
    };

    /* DHE Test: DH public key range validation per RFC 2631 §2.1.5
     * Valid range is [2, p-1]; values outside must be rejected. */
    {
        struct s2n_stuffer dhparams_in = { 0 };
        struct s2n_stuffer dhparams_out = { 0 };
        struct s2n_dh_params base_params = { 0 };

        EXPECT_SUCCESS(s2n_stuffer_alloc(&dhparams_in, sizeof(dhparams_pem)));
        EXPECT_SUCCESS(s2n_stuffer_alloc(&dhparams_out, sizeof(dhparams_pem)));
        EXPECT_SUCCESS(s2n_stuffer_write_bytes(&dhparams_in, (uint8_t *) dhparams_pem, sizeof(dhparams_pem)));
        EXPECT_SUCCESS(s2n_stuffer_dhparams_from_pem(&dhparams_in, &dhparams_out));

        uint32_t available_size = s2n_stuffer_data_available(&dhparams_out);
        struct s2n_blob dhparams_blob = { 0 };
        EXPECT_SUCCESS(s2n_blob_init(&dhparams_blob, s2n_stuffer_raw_read(&dhparams_out, available_size), available_size));

        /* Skip if DH param validation fails (libcrypto-dependent) */
        if (s2n_pkcs3_to_dh_params(&base_params, &dhparams_blob) == S2N_SUCCESS) {
            EXPECT_SUCCESS(s2n_dh_generate_ephemeral_key(&base_params));

            struct s2n_stuffer pgy_out = { 0 };
            struct s2n_blob pgy_blob = { 0 };
            EXPECT_SUCCESS(s2n_stuffer_alloc(&pgy_out, 1024));
            EXPECT_SUCCESS(s2n_dh_params_to_p_g_Ys(&base_params, &pgy_out, &pgy_blob));

            /* Parse serialized format: [uint16 p_len][p][uint16 g_len][g][uint16 Ys_len][Ys] */
            uint16_t p_len = 0;
            uint16_t g_len = 0;
            EXPECT_SUCCESS(s2n_stuffer_read_uint16(&pgy_out, &p_len));
            uint8_t *p_data = s2n_stuffer_raw_read(&pgy_out, p_len);
            EXPECT_NOT_NULL(p_data);
            EXPECT_SUCCESS(s2n_stuffer_read_uint16(&pgy_out, &g_len));
            uint8_t *g_data = s2n_stuffer_raw_read(&pgy_out, g_len);
            EXPECT_NOT_NULL(g_data);

            struct s2n_blob p_blob = { 0 };
            struct s2n_blob g_blob = { 0 };
            EXPECT_SUCCESS(s2n_blob_init(&p_blob, p_data, p_len));
            EXPECT_SUCCESS(s2n_blob_init(&g_blob, g_data, g_len));

            /* Get p as a BIGNUM for constructing boundary test values */
            BIGNUM *bn_p = BN_bin2bn(p_data, p_len, NULL);
            EXPECT_NOT_NULL(bn_p);
            struct {
                BIGNUM *ys;
                bool expect_success;
            } test_cases[] = {
                { .ys = BN_new(), .expect_success = false },     /* Ys = 1 (below valid range) */
                { .ys = BN_new(), .expect_success = true },      /* Ys = 2 (min valid) */
                { .ys = BN_dup(bn_p), .expect_success = true },  /* Ys = p-1 (max valid) */
                { .ys = BN_dup(bn_p), .expect_success = false }, /* Ys = p (above valid range) */
            };
            BN_set_word(test_cases[0].ys, 1);
            BN_set_word(test_cases[1].ys, 2);
            BN_sub_word(test_cases[2].ys, 1);
            /* test_cases[3].ys is already p */

            for (size_t i = 0; i < s2n_array_len(test_cases); i++) {
                uint8_t ys_buf[256] = { 0 };
                int ys_len = BN_bn2bin(test_cases[i].ys, ys_buf);
                struct s2n_blob ys_blob = { 0 };
                EXPECT_SUCCESS(s2n_blob_init(&ys_blob, ys_buf, ys_len));

                struct s2n_dh_params test_params = { 0 };
                if (test_cases[i].expect_success) {
                    EXPECT_SUCCESS(s2n_dh_p_g_Ys_to_dh_params(&test_params, &p_blob, &g_blob, &ys_blob));
                } else {
                    EXPECT_FAILURE_WITH_ERRNO(
                            s2n_dh_p_g_Ys_to_dh_params(&test_params, &p_blob, &g_blob, &ys_blob),
                            S2N_ERR_DH_PARAMS_CREATE);
                }
                EXPECT_SUCCESS(s2n_dh_params_free(&test_params));
                BN_free(test_cases[i].ys);
            }
            BN_free(bn_p);
            EXPECT_SUCCESS(s2n_stuffer_free(&pgy_out));
        }
        EXPECT_SUCCESS(s2n_dh_params_free(&base_params));
        EXPECT_SUCCESS(s2n_stuffer_free(&dhparams_in));
        EXPECT_SUCCESS(s2n_stuffer_free(&dhparams_out));
    };

    END_TEST();
}
