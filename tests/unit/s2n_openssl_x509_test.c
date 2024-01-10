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
#include "crypto/s2n_openssl_x509.h"

#include "s2n_test.h"
#include "testlib/s2n_testlib.h"
#include "tls/s2n_x509_validator.h"

static S2N_RESULT s2n_x509_validator_read_asn1_cert(struct s2n_stuffer* cert_chain_in_stuffer, struct s2n_blob* asn1_cert)
{
    uint32_t certificate_size = 0;

    RESULT_GUARD_POSIX(s2n_stuffer_read_uint24(cert_chain_in_stuffer, &certificate_size));
    RESULT_ENSURE(certificate_size > 0, S2N_ERR_CERT_INVALID);
    RESULT_ENSURE(certificate_size <= s2n_stuffer_data_available(cert_chain_in_stuffer), S2N_ERR_CERT_INVALID);

    asn1_cert->size = certificate_size;
    asn1_cert->data = s2n_stuffer_raw_read(cert_chain_in_stuffer, certificate_size);
    RESULT_ENSURE_REF(asn1_cert->data);

    return S2N_RESULT_OK;
}

int main(int argc, char** argv)
{
    BEGIN_TEST();

    /* s2n_asn1der_to_public_key_and_type tests */
    {
        /* A certificate with one trailing byte is parsed successfully */
        {
            uint8_t cert_chain_data[S2N_MAX_TEST_PEM_SIZE] = { 0 };
            uint32_t cert_chain_len = 0;
            EXPECT_SUCCESS(s2n_read_test_pem_and_len(S2N_ONE_TRAILING_BYTE_CERT_BIN, cert_chain_data, &cert_chain_len,
                    S2N_MAX_TEST_PEM_SIZE));

            struct s2n_blob cert_chain_blob = { 0 };
            EXPECT_SUCCESS(s2n_blob_init(&cert_chain_blob, cert_chain_data, cert_chain_len));

            DEFER_CLEANUP(struct s2n_stuffer cert_chain_stuffer = { 0 }, s2n_stuffer_free);
            EXPECT_SUCCESS(s2n_stuffer_init_written(&cert_chain_stuffer, &cert_chain_blob));

            struct s2n_blob cert_asn1_der = { 0 };
            EXPECT_OK(s2n_x509_validator_read_asn1_cert(&cert_chain_stuffer, &cert_asn1_der));

            {
                DEFER_CLEANUP(X509* cert = NULL, X509_free_pointer);
                EXPECT_OK(s2n_openssl_x509_parse(&cert_asn1_der, &cert));
            }
            {
                DEFER_CLEANUP(X509* cert = NULL, X509_free_pointer);
                EXPECT_OK(s2n_openssl_x509_parse_without_length_validation(&cert_asn1_der, &cert));
            }
        }

        /* A certificate with too many trailing bytes errors */
        {
            uint8_t cert_chain_data[S2N_MAX_TEST_PEM_SIZE] = { 0 };
            uint32_t cert_chain_len = 0;
            EXPECT_SUCCESS(s2n_read_test_pem_and_len(S2N_FOUR_TRAILING_BYTE_CERT_BIN, cert_chain_data, &cert_chain_len,
                    S2N_MAX_TEST_PEM_SIZE));

            struct s2n_blob cert_chain_blob = { 0 };
            EXPECT_SUCCESS(s2n_blob_init(&cert_chain_blob, cert_chain_data, cert_chain_len));

            DEFER_CLEANUP(struct s2n_stuffer cert_chain_stuffer = { 0 }, s2n_stuffer_free);
            EXPECT_SUCCESS(s2n_stuffer_init_written(&cert_chain_stuffer, &cert_chain_blob));

            struct s2n_blob cert_asn1_der = { 0 };
            EXPECT_OK(s2n_x509_validator_read_asn1_cert(&cert_chain_stuffer, &cert_asn1_der));

            {
                DEFER_CLEANUP(X509* cert = NULL, X509_free_pointer);
                EXPECT_ERROR(s2n_openssl_x509_parse(&cert_asn1_der, &cert));
            }
            {
                DEFER_CLEANUP(X509* cert = NULL, X509_free_pointer);
                EXPECT_OK(s2n_openssl_x509_parse_without_length_validation(&cert_asn1_der, &cert));
            }
        }
    }

    END_TEST();
}
