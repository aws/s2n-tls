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
#include "testlib/s2n_testlib.h"
#include "tls/s2n_crl.h"

#define S2N_CRL_ROOT_CERT                               "../pems/crl/root_cert.pem"
#define S2N_CRL_NONE_REVOKED_CERT_CHAIN                 "../pems/crl/none_revoked_cert_chain.pem"
#define S2N_CRL_NONE_REVOKED_KEY                        "../pems/crl/none_revoked_key.pem"
#define S2N_CRL_INTERMEDIATE_REVOKED_CERT_CHAIN         "../pems/crl/intermediate_revoked_cert_chain.pem"
#define S2N_CRL_INTERMEDIATE_REVOKED_KEY                "../pems/crl/intermediate_revoked_key.pem"
#define S2N_CRL_LEAF_REVOKED_CERT_CHAIN                 "../pems/crl/leaf_revoked_cert_chain.pem"
#define S2N_CRL_LEAF_REVOKED_KEY                        "../pems/crl/leaf_revoked_key.pem"
#define S2N_CRL_ALL_REVOKED_CERT_CHAIN                  "../pems/crl/all_revoked_cert_chain.pem"
#define S2N_CRL_ALL_REVOKED_KEY                         "../pems/crl/all_revoked_key.pem"
#define S2N_CRL_ROOT_CRL                                "../pems/crl/root_crl.pem"
#define S2N_CRL_INTERMEDIATE_CRL                        "../pems/crl/intermediate_crl.pem"
#define S2N_CRL_INTERMEDIATE_REVOKED_CRL                "../pems/crl/intermediate_revoked_crl.pem"
#define S2N_CRL_INTERMEDIATE_INVALID_LAST_UPDATE_CRL    "../pems/crl/intermediate_invalid_last_update_crl.pem"
#define S2N_CRL_INTERMEDIATE_INVALID_NEXT_UPDATE_CRL    "../pems/crl/intermediate_invalid_next_update_crl.pem"

int main(int argc, char *argv[])
{
    BEGIN_TEST();

    /* s2n_crl_new allocates and frees a s2n_crl */
    {
        struct s2n_crl *crl = s2n_crl_new();
        EXPECT_NOT_NULL(crl);

        EXPECT_SUCCESS(s2n_crl_free(&crl));
        EXPECT_NULL(crl);

        /* Multiple calls to free succeed */
        EXPECT_SUCCESS(s2n_crl_free(&crl));
        EXPECT_NULL(crl);
    }

    /* s2n_crl_new allocates and frees a s2n_crl with an internal X509_CRL set */
    {
        uint8_t crl_pem[S2N_MAX_TEST_PEM_SIZE] = { 0 };
        uint32_t crl_pem_len = 0;
        EXPECT_SUCCESS(s2n_read_test_pem_and_len(S2N_CRL_ROOT_CRL, crl_pem, &crl_pem_len, S2N_MAX_TEST_PEM_SIZE));
        struct s2n_crl *crl = s2n_crl_new();
        EXPECT_NOT_NULL(crl);

        EXPECT_SUCCESS(s2n_crl_load_pem(crl, crl_pem, crl_pem_len));
        EXPECT_NOT_NULL(crl->crl);

        EXPECT_SUCCESS(s2n_crl_free(&crl));
        EXPECT_NULL(crl);

        /* Multiple calls to free succeed */
        EXPECT_SUCCESS(s2n_crl_free(&crl));
        EXPECT_NULL(crl);
    }

    /* Ensure s2n_crl_load_pem produces a valid X509_CRL internally */
    {
        uint8_t crl_pem[S2N_MAX_TEST_PEM_SIZE] = { 0 };
        uint32_t crl_pem_len = 0;
        EXPECT_SUCCESS(s2n_read_test_pem_and_len(S2N_CRL_ROOT_CRL, crl_pem, &crl_pem_len, S2N_MAX_TEST_PEM_SIZE));
        DEFER_CLEANUP(struct s2n_crl *crl = s2n_crl_new(), s2n_crl_free);
        EXPECT_NOT_NULL(crl);
        EXPECT_SUCCESS(s2n_crl_load_pem(crl, crl_pem, crl_pem_len));

        /* Make sure an OpenSSL operation succeeds on the internal X509_CRL */
        X509_NAME *crl_name = X509_CRL_get_issuer(crl->crl);
        POSIX_ENSURE_REF(crl_name);
    }

    /* s2n_crl_load_pem fails if provided a bad pem */
    {
        uint8_t crl_pem[S2N_MAX_TEST_PEM_SIZE] = { 0 };
        uint32_t crl_pem_len = 0;
        EXPECT_SUCCESS(s2n_read_test_pem_and_len(S2N_CRL_ROOT_CRL, crl_pem, &crl_pem_len, S2N_MAX_TEST_PEM_SIZE));
        DEFER_CLEANUP(struct s2n_crl *crl = s2n_crl_new(), s2n_crl_free);
        EXPECT_NOT_NULL(crl);
        EXPECT_SUCCESS(s2n_crl_load_pem(crl, crl_pem, crl_pem_len));

        /* Change a random byte in the pem to make it invalid */
        crl_pem[50] = 1;

        DEFER_CLEANUP(struct s2n_crl *invalid_crl = s2n_crl_new(), s2n_crl_free);
        EXPECT_NOT_NULL(invalid_crl);
        EXPECT_FAILURE_WITH_ERRNO(s2n_crl_load_pem(invalid_crl, crl_pem, crl_pem_len),
                S2N_ERR_INVALID_PEM);
    }

    /* CRL issuer hash is retrieved successfully */
    {
        uint8_t crl_pem[S2N_MAX_TEST_PEM_SIZE] = { 0 };
        uint32_t crl_pem_len = 0;
        EXPECT_SUCCESS(s2n_read_test_pem_and_len(S2N_CRL_ROOT_CRL, crl_pem, &crl_pem_len, S2N_MAX_TEST_PEM_SIZE));
        DEFER_CLEANUP(struct s2n_crl *crl = s2n_crl_new(), s2n_crl_free);
        EXPECT_NOT_NULL(crl);
        EXPECT_SUCCESS(s2n_crl_load_pem(crl, crl_pem, crl_pem_len));

        uint64_t hash = 0;
        EXPECT_SUCCESS(s2n_crl_get_issuer_hash(crl, &hash));
        EXPECT_TRUE(hash != 0);
    }

    END_TEST();
}
