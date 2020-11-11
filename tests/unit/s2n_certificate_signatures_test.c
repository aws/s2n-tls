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
        &s2n_rsa_pkcs1_sha1,
    };

    const struct s2n_signature_preferences test_certificate_signature_preferences = {
        .count = s2n_array_len(test_sig_scheme_list),
        .signature_schemes = test_sig_scheme_list,
    };

    /* s2n_is_certificate_sig_scheme_supported() */
    {
        struct s2n_config *config = s2n_config_new();
        struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT);
        s2n_connection_set_config(conn, config);

        const struct s2n_security_policy *security_policy = NULL;
        EXPECT_SUCCESS(s2n_connection_get_security_policy(conn, &security_policy));
        EXPECT_NOT_NULL(security_policy);

        struct s2n_security_policy test_security_policy = {
            .minimum_protocol_version = security_policy->minimum_protocol_version,
            .cipher_preferences = security_policy->cipher_preferences,
            .kem_preferences = security_policy->kem_preferences,
            .signature_preferences = security_policy->signature_preferences,
            .certificate_signature_preferences = &test_certificate_signature_preferences,
            .ecc_preferences = security_policy->ecc_preferences,
        };

        config->security_policy = &test_security_policy;

        /* Certificate signature algorithm is in test certificate signature preferences list */
        {
            EXPECT_SUCCESS(s2n_read_test_pem(S2N_ECDSA_P256_PKCS1_CERT_CHAIN, (char *)cert_file, S2N_MAX_TEST_PEM_SIZE));
            certLen = strlen((const char*)cert_file);

            /* Read the test certificates into an Openssl X509 struct */
            certBio = BIO_new(BIO_s_mem());
            BIO_write(certBio, cert_file, certLen);
            cert = PEM_read_bio_X509(certBio, NULL, NULL, NULL);
            S2N_ERROR_IF(cert == NULL, S2N_ERR_DECODE_CERTIFICATE);

            EXPECT_OK(s2n_is_certificate_sig_scheme_supported(conn, cert, &out));
            EXPECT_TRUE(out);

            BIO_free(certBio);
            X509_free(cert);
        }

        /* Certificate signature algorithm is not in test certificate signature preferences list */
        {
            EXPECT_SUCCESS(s2n_read_test_pem(S2N_RSA_PSS_2048_SHA256_LEAF_CERT, (char *)cert_file, S2N_MAX_TEST_PEM_SIZE));
            certLen = strlen((const char*)cert_file);

            /* Read the test certificates into an Openssl X509 struct */
            certBio = BIO_new(BIO_s_mem());
            BIO_write(certBio, cert_file, certLen);
            cert = PEM_read_bio_X509(certBio, NULL, NULL, NULL);
            S2N_ERROR_IF(cert == NULL, S2N_ERR_DECODE_CERTIFICATE);

            EXPECT_OK(s2n_is_certificate_sig_scheme_supported(conn, cert, &out));
            EXPECT_FALSE(out);

            BIO_free(certBio);
            X509_free(cert);
        }

        /* Certificate signature algorithm is in the test certificate signature preferences list but signature is SHA-1
         * and TLS 1.3 has been negotiated.
         */
        {
            conn->actual_protocol_version = S2N_TLS13;
            EXPECT_SUCCESS(s2n_read_test_pem(S2N_RSA_2048_PKCS1_CERT_CHAIN, (char *)cert_file, S2N_MAX_TEST_PEM_SIZE));
            certLen = strlen((const char*)cert_file);

            /* Read the test certificates into an Openssl X509 struct */
            certBio = BIO_new(BIO_s_mem());
            BIO_write(certBio, cert_file, certLen);
            cert = PEM_read_bio_X509(certBio, NULL, NULL, NULL);
            S2N_ERROR_IF(cert == NULL, S2N_ERR_DECODE_CERTIFICATE);

            EXPECT_OK(s2n_is_certificate_sig_scheme_supported(conn, cert, &out));
            EXPECT_FALSE(out);

            BIO_free(certBio);
            X509_free(cert);
        }

        /* Certificate signature algorithm is in the test certificate signature preferences list and signature is SHA-1
         * and TLS 1.2 has been negotiated.
         */
        {
            conn->actual_protocol_version = S2N_TLS12;
            EXPECT_SUCCESS(s2n_read_test_pem(S2N_RSA_2048_PKCS1_CERT_CHAIN, (char *)cert_file, S2N_MAX_TEST_PEM_SIZE));
            certLen = strlen((const char*)cert_file);

            /* Read the test certificates into an Openssl X509 struct */
            certBio = BIO_new(BIO_s_mem());
            BIO_write(certBio, cert_file, certLen);
            cert = PEM_read_bio_X509(certBio, NULL, NULL, NULL);
            S2N_ERROR_IF(cert == NULL, S2N_ERR_DECODE_CERTIFICATE);

            EXPECT_OK(s2n_is_certificate_sig_scheme_supported(conn, cert, &out));
            EXPECT_TRUE(out);

            BIO_free(certBio);
            X509_free(cert);
        }
        EXPECT_SUCCESS(s2n_connection_free(conn));
        EXPECT_SUCCESS(s2n_config_free(config));

    }
    END_TEST();
    return S2N_SUCCESS;
}
