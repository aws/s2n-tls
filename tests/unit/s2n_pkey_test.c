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

#include "crypto/s2n_rsa_pss.h"
#include "s2n_test.h"
#include "testlib/s2n_testlib.h"

int main(int argc, char **argv)
{
    BEGIN_TEST();
    EXPECT_SUCCESS(s2n_disable_tls13_in_test());

    /* Test each combination of s2n_pkey_types to validate that only keys of
     * the same type can be compared */
    {
        struct s2n_cert_chain_and_key *chain_and_key;
        char rsa_cert_chain_pem[S2N_MAX_TEST_PEM_SIZE] = { 0 };
        char rsa_pss_cert_chain_pem[S2N_MAX_TEST_PEM_SIZE] = { 0 };
        char ecdsa_cert_chain_pem[S2N_MAX_TEST_PEM_SIZE] = { 0 };
        char rsa_private_key_pem[S2N_MAX_TEST_PEM_SIZE] = { 0 };
        char rsa_pss_private_key_pem[S2N_MAX_TEST_PEM_SIZE] = { 0 };
        char ecdsa_private_key_pem[S2N_MAX_TEST_PEM_SIZE] = { 0 };

        EXPECT_SUCCESS(s2n_read_test_pem(S2N_RSA_2048_PKCS1_CERT_CHAIN, rsa_cert_chain_pem, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_RSA_PSS_2048_SHA256_CA_CERT, rsa_pss_cert_chain_pem, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_ECDSA_P384_PKCS1_CERT_CHAIN, ecdsa_cert_chain_pem, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_RSA_2048_PKCS1_KEY, rsa_private_key_pem, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_RSA_PSS_2048_SHA256_CA_KEY, rsa_pss_private_key_pem, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_ECDSA_P384_PKCS1_KEY, ecdsa_private_key_pem, S2N_MAX_TEST_PEM_SIZE));

        /* Keys of the same type can be compared */
        EXPECT_NOT_NULL(chain_and_key = s2n_cert_chain_and_key_new());
        EXPECT_SUCCESS(s2n_cert_chain_and_key_load_pem(chain_and_key, rsa_cert_chain_pem, rsa_private_key_pem));
        EXPECT_SUCCESS(s2n_cert_chain_and_key_free(chain_and_key));

        if (s2n_is_rsa_pss_certs_supported()) {
            EXPECT_NOT_NULL(chain_and_key = s2n_cert_chain_and_key_new());
            EXPECT_SUCCESS(
                    s2n_cert_chain_and_key_load_pem(chain_and_key, rsa_pss_cert_chain_pem, rsa_pss_private_key_pem));
            EXPECT_SUCCESS(s2n_cert_chain_and_key_free(chain_and_key));
        }

        EXPECT_NOT_NULL(chain_and_key = s2n_cert_chain_and_key_new());
        EXPECT_SUCCESS(s2n_cert_chain_and_key_load_pem(chain_and_key, ecdsa_cert_chain_pem, ecdsa_private_key_pem));
        EXPECT_SUCCESS(s2n_cert_chain_and_key_free(chain_and_key));

        /* Keys of different types cannot be compared */
        EXPECT_NOT_NULL(chain_and_key = s2n_cert_chain_and_key_new());
        EXPECT_FAILURE_WITH_ERRNO(s2n_cert_chain_and_key_load_pem(chain_and_key, rsa_cert_chain_pem, ecdsa_private_key_pem),
                S2N_ERR_KEY_MISMATCH);
        EXPECT_SUCCESS(s2n_cert_chain_and_key_free(chain_and_key));

        EXPECT_NOT_NULL(chain_and_key = s2n_cert_chain_and_key_new());
        EXPECT_FAILURE_WITH_ERRNO(s2n_cert_chain_and_key_load_pem(chain_and_key, ecdsa_cert_chain_pem, rsa_private_key_pem),
                S2N_ERR_KEY_MISMATCH);
        EXPECT_SUCCESS(s2n_cert_chain_and_key_free(chain_and_key));

        if (s2n_is_rsa_pss_certs_supported()) {
            EXPECT_NOT_NULL(chain_and_key = s2n_cert_chain_and_key_new());
            EXPECT_FAILURE_WITH_ERRNO(
                    s2n_cert_chain_and_key_load_pem(chain_and_key, rsa_cert_chain_pem, rsa_pss_private_key_pem),
                    S2N_ERR_KEY_MISMATCH);
            EXPECT_SUCCESS(s2n_cert_chain_and_key_free(chain_and_key));

            EXPECT_NOT_NULL(chain_and_key = s2n_cert_chain_and_key_new());
            EXPECT_FAILURE_WITH_ERRNO(s2n_cert_chain_and_key_load_pem(chain_and_key, rsa_pss_cert_chain_pem, rsa_private_key_pem),
                    S2N_ERR_KEY_MISMATCH);
            EXPECT_SUCCESS(s2n_cert_chain_and_key_free(chain_and_key));

            EXPECT_NOT_NULL(chain_and_key = s2n_cert_chain_and_key_new());
            EXPECT_FAILURE_WITH_ERRNO(s2n_cert_chain_and_key_load_pem(chain_and_key, rsa_pss_cert_chain_pem, ecdsa_private_key_pem),
                    S2N_ERR_KEY_MISMATCH);
            EXPECT_SUCCESS(s2n_cert_chain_and_key_free(chain_and_key));

            EXPECT_NOT_NULL(chain_and_key = s2n_cert_chain_and_key_new());
            EXPECT_FAILURE_WITH_ERRNO(s2n_cert_chain_and_key_load_pem(chain_and_key, ecdsa_cert_chain_pem, rsa_pss_private_key_pem),
                    S2N_ERR_KEY_MISMATCH);
            EXPECT_SUCCESS(s2n_cert_chain_and_key_free(chain_and_key));
        }
    };

    /* Test the same as above but with non null terminated chain and key and
     * api that accepts length  */
    {
        struct s2n_cert_chain_and_key *chain_and_key;
        uint8_t rsa_cert_chain_pem[S2N_MAX_TEST_PEM_SIZE] = { 0 };
        uint8_t rsa_pss_cert_chain_pem[S2N_MAX_TEST_PEM_SIZE] = { 0 };
        uint8_t ecdsa_cert_chain_pem[S2N_MAX_TEST_PEM_SIZE] = { 0 };
        uint8_t rsa_private_key_pem[S2N_MAX_TEST_PEM_SIZE] = { 0 };
        uint8_t rsa_pss_private_key_pem[S2N_MAX_TEST_PEM_SIZE] = { 0 };
        uint8_t ecdsa_private_key_pem[S2N_MAX_TEST_PEM_SIZE] = { 0 };

        uint32_t rsa_cert_chain_len = 0;
        uint32_t rsa_pss_cert_chain_len = 0;
        uint32_t ecdsa_cert_chain_len = 0;
        uint32_t rsa_private_key_len = 0;
        uint32_t rsa_pss_private_key_len = 0;
        uint32_t ecdsa_private_key_len = 0;

        EXPECT_SUCCESS(s2n_read_test_pem_and_len(S2N_RSA_2048_PKCS1_CERT_CHAIN, rsa_cert_chain_pem, &rsa_cert_chain_len, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(s2n_read_test_pem_and_len(S2N_RSA_PSS_2048_SHA256_CA_CERT, rsa_pss_cert_chain_pem, &rsa_pss_cert_chain_len, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(s2n_read_test_pem_and_len(S2N_ECDSA_P384_PKCS1_CERT_CHAIN, ecdsa_cert_chain_pem, &ecdsa_cert_chain_len, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(s2n_read_test_pem_and_len(S2N_RSA_2048_PKCS1_KEY, rsa_private_key_pem, &rsa_private_key_len, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(s2n_read_test_pem_and_len(S2N_RSA_PSS_2048_SHA256_CA_KEY, rsa_pss_private_key_pem, &rsa_pss_private_key_len, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(s2n_read_test_pem_and_len(S2N_ECDSA_P384_PKCS1_KEY, ecdsa_private_key_pem, &ecdsa_private_key_len, S2N_MAX_TEST_PEM_SIZE));

        /* Keys of the same type can be compared */
        EXPECT_NOT_NULL(chain_and_key = s2n_cert_chain_and_key_new());
        EXPECT_SUCCESS(s2n_cert_chain_and_key_load_pem_bytes(chain_and_key, rsa_cert_chain_pem, rsa_cert_chain_len, rsa_private_key_pem, rsa_private_key_len));
        EXPECT_SUCCESS(s2n_cert_chain_and_key_free(chain_and_key));

        if (s2n_is_rsa_pss_certs_supported()) {
            EXPECT_NOT_NULL(chain_and_key = s2n_cert_chain_and_key_new());
            EXPECT_SUCCESS(
                    s2n_cert_chain_and_key_load_pem_bytes(chain_and_key, rsa_pss_cert_chain_pem, rsa_pss_cert_chain_len, rsa_pss_private_key_pem, rsa_pss_private_key_len));
            EXPECT_SUCCESS(s2n_cert_chain_and_key_free(chain_and_key));
        }

        EXPECT_NOT_NULL(chain_and_key = s2n_cert_chain_and_key_new());
        EXPECT_SUCCESS(s2n_cert_chain_and_key_load_pem_bytes(chain_and_key, ecdsa_cert_chain_pem, ecdsa_cert_chain_len, ecdsa_private_key_pem, ecdsa_private_key_len));
        EXPECT_SUCCESS(s2n_cert_chain_and_key_free(chain_and_key));

        /* Keys of different types cannot be compared */
        EXPECT_NOT_NULL(chain_and_key = s2n_cert_chain_and_key_new());
        EXPECT_FAILURE_WITH_ERRNO(s2n_cert_chain_and_key_load_pem_bytes(chain_and_key, rsa_cert_chain_pem, rsa_cert_chain_len, ecdsa_private_key_pem, ecdsa_private_key_len),
                S2N_ERR_KEY_MISMATCH);
        EXPECT_SUCCESS(s2n_cert_chain_and_key_free(chain_and_key));

        EXPECT_NOT_NULL(chain_and_key = s2n_cert_chain_and_key_new());
        EXPECT_FAILURE_WITH_ERRNO(s2n_cert_chain_and_key_load_pem_bytes(chain_and_key, ecdsa_cert_chain_pem, ecdsa_cert_chain_len, rsa_private_key_pem, rsa_private_key_len),
                S2N_ERR_KEY_MISMATCH);
        EXPECT_SUCCESS(s2n_cert_chain_and_key_free(chain_and_key));

        if (s2n_is_rsa_pss_certs_supported()) {
            EXPECT_NOT_NULL(chain_and_key = s2n_cert_chain_and_key_new());
            EXPECT_FAILURE_WITH_ERRNO(
                    s2n_cert_chain_and_key_load_pem_bytes(chain_and_key, rsa_cert_chain_pem, rsa_cert_chain_len, rsa_pss_private_key_pem, rsa_pss_private_key_len),
                    S2N_ERR_KEY_MISMATCH);
            EXPECT_SUCCESS(s2n_cert_chain_and_key_free(chain_and_key));

            EXPECT_NOT_NULL(chain_and_key = s2n_cert_chain_and_key_new());
            EXPECT_FAILURE_WITH_ERRNO(s2n_cert_chain_and_key_load_pem_bytes(chain_and_key, rsa_pss_cert_chain_pem, rsa_pss_cert_chain_len, rsa_private_key_pem, rsa_private_key_len),
                    S2N_ERR_KEY_MISMATCH);
            EXPECT_SUCCESS(s2n_cert_chain_and_key_free(chain_and_key));

            EXPECT_NOT_NULL(chain_and_key = s2n_cert_chain_and_key_new());
            EXPECT_FAILURE_WITH_ERRNO(s2n_cert_chain_and_key_load_pem_bytes(chain_and_key, rsa_pss_cert_chain_pem, rsa_pss_cert_chain_len, ecdsa_private_key_pem, ecdsa_private_key_len),
                    S2N_ERR_KEY_MISMATCH);
            EXPECT_SUCCESS(s2n_cert_chain_and_key_free(chain_and_key));

            EXPECT_NOT_NULL(chain_and_key = s2n_cert_chain_and_key_new());
            EXPECT_FAILURE_WITH_ERRNO(s2n_cert_chain_and_key_load_pem_bytes(chain_and_key, ecdsa_cert_chain_pem, ecdsa_cert_chain_len, rsa_pss_private_key_pem, rsa_pss_private_key_len),
                    S2N_ERR_KEY_MISMATCH);
            EXPECT_SUCCESS(s2n_cert_chain_and_key_free(chain_and_key));
        }
    };

    END_TEST();
}
