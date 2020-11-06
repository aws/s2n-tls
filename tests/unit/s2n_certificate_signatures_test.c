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

#include <string.h>
#include <stdio.h>
#include <s2n.h>

#include <openssl/x509.h>
 #include <openssl/pem.h>

#include "s2n_test.h"
#include "testlib/s2n_testlib.h"

#include "tls/s2n_signature_scheme.h"
#include "tls/s2n_tls.h"
#include "tls/s2n_tls13.h"
#include "tls/s2n_x509_validator.h"

#include "error/s2n_errno.h"
#include "utils/s2n_safety.h"
#include "crypto/s2n_openssl.h"
#include "crypto/s2n_openssl_x509.h"

int main(int argc, char **argv)
{
    BEGIN_TEST();

    uint8_t cert_file[S2N_MAX_TEST_PEM_SIZE];
    X509 *cert;
    bool out;
    BIO* certBio;
    size_t certLen;
    
    const struct s2n_signature_scheme* const test_sig_scheme_list[] = {
        &s2n_ecdsa_sha256,
    };

    const struct s2n_signature_preferences test_certificate_signature_preferences = {
        .count = s2n_array_len(test_sig_scheme_list),
        .signature_schemes = test_sig_scheme_list,
    };

    /* s2n_is_certificate_sig_scheme_supported() */
    {
        /* Certificate signature algorithm is in certificate signature preferences list */
        {
            EXPECT_SUCCESS(s2n_read_test_pem(S2N_ECDSA_P256_PKCS1_CERT_CHAIN, (char *)cert_file, S2N_MAX_TEST_PEM_SIZE));
            certLen = strlen((const char*)cert_file);

            /* Read the test certificates into an Openssl X509 struct */
            certBio = BIO_new(BIO_s_mem());
            BIO_write(certBio, cert_file, certLen);
            cert = PEM_read_bio_X509(certBio, NULL, NULL, NULL);
            S2N_ERROR_IF(cert == NULL, S2N_ERR_DECODE_CERTIFICATE);

            EXPECT_OK(s2n_is_certificate_sig_scheme_supported(cert, &test_certificate_signature_preferences, &out));
            EXPECT_TRUE(out);

            BIO_free(certBio);
            X509_free(cert);
        }

        /* Certificate signature algorithm is not in certificate signature preferences list */
        {
            EXPECT_SUCCESS(s2n_read_test_pem(S2N_RSA_2048_PKCS1_CERT_CHAIN, (char *)cert_file, S2N_MAX_TEST_PEM_SIZE));
            certLen = strlen((const char*)cert_file);

            /* Read the test certificates into an Openssl X509 struct */
            certBio = BIO_new(BIO_s_mem());
            BIO_write(certBio, cert_file, certLen);
            cert = PEM_read_bio_X509(certBio, NULL, NULL, NULL);
            S2N_ERROR_IF(cert == NULL, S2N_ERR_DECODE_CERTIFICATE);

            EXPECT_OK(s2n_is_certificate_sig_scheme_supported(cert, &test_certificate_signature_preferences, &out));
            EXPECT_FALSE(out);

            BIO_free(certBio);
            X509_free(cert);
        }
    }

    END_TEST();
    return S2N_SUCCESS;
}
