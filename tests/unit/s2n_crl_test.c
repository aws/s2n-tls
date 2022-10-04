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

#define CRL_TEST_CHAIN_LEN 2

DEFINE_POINTER_CLEANUP_FUNC(struct s2n_x509_crl*, s2n_x509_crl_free);

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

int free_uint8_array_pointer(uint8_t** array) {
    if (array && *array) {
        free(*array);
    }
    return S2N_SUCCESS;
}

int main(int argc, char *argv[])
{
    BEGIN_TEST();

    DEFER_CLEANUP(uint8_t *root_crl_pem = malloc(S2N_MAX_TEST_PEM_SIZE), free_uint8_array_pointer);
    EXPECT_NOT_NULL(root_crl_pem);
    uint32_t root_crl_pem_len = 0;
    EXPECT_SUCCESS(s2n_read_test_pem_and_len(S2N_CRL_ROOT_CRL, root_crl_pem, &root_crl_pem_len, S2N_MAX_TEST_PEM_SIZE));
    DEFER_CLEANUP(struct s2n_x509_crl *root_crl = NULL, s2n_x509_crl_free_pointer);
    EXPECT_SUCCESS(s2n_x509_crl_from_pem(root_crl_pem, root_crl_pem_len, &root_crl));

    /* Ensure s2n_x509_crl_from_pem produces a valid X509_CRL internally */
    {
        EXPECT_NOT_NULL(root_crl->crl);

        /* Make sure an OpenSSL operation succeeds on the internal X509_CRL */
        X509_NAME *crl_name = X509_CRL_get_issuer(root_crl->crl);
        POSIX_ENSURE_REF(crl_name);
    }

    /* s2n_x509_crl_from_pem fails if provided a bad pem */
    {
        DEFER_CLEANUP(uint8_t *invalid_crl_pem = malloc(S2N_MAX_TEST_PEM_SIZE), free_uint8_array_pointer);
        EXPECT_NOT_NULL(invalid_crl_pem);
        uint32_t invalid_crl_pem_len = 0;
        EXPECT_SUCCESS(s2n_read_test_pem_and_len(S2N_CRL_ROOT_CRL, invalid_crl_pem, &invalid_crl_pem_len,
                S2N_MAX_TEST_PEM_SIZE));

        /* Change a random byte in the pem to make it invalid */
        invalid_crl_pem[50] = 1;

        DEFER_CLEANUP(struct s2n_x509_crl *invalid_crl = NULL, s2n_x509_crl_free_pointer);
        EXPECT_FAILURE_WITH_ERRNO(s2n_x509_crl_from_pem(invalid_crl_pem, invalid_crl_pem_len, &invalid_crl),
                S2N_ERR_INTERNAL_LIBCRYPTO_ERROR);
    }

    /* CRL issuer hash is retrieved successfully */
    {
        unsigned long hash = 0;
        EXPECT_SUCCESS(s2n_x509_crl_get_issuer_hash(root_crl, &hash));
        EXPECT_TRUE(hash != 0);
    }

    END_TEST();
}