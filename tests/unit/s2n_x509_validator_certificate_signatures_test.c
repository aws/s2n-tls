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

#include <openssl/pem.h>
#include <openssl/x509.h>
#include <stdio.h>
#include <string.h>

#include "api/s2n.h"
#include "crypto/s2n_openssl.h"
#include "crypto/s2n_openssl_x509.h"
#include "error/s2n_errno.h"
#include "s2n_test.h"
#include "testlib/s2n_testlib.h"
#include "tls/s2n_signature_scheme.h"
#include "tls/s2n_tls.h"
#include "tls/s2n_tls13.h"
#include "tls/s2n_x509_validator.h"
#include "utils/s2n_safety.h"

int main(int argc, char **argv)
{
    BEGIN_TEST();

    uint8_t cert_file[S2N_MAX_TEST_PEM_SIZE] = { 0 };
    X509 *cert = NULL;
    BIO *certBio = NULL;
    size_t certLen = 0;

    const struct s2n_signature_scheme *const test_sig_scheme_list[] = {
        &s2n_ecdsa_sha256,
        &s2n_rsa_pkcs1_sha1,
    };

    const struct s2n_signature_preferences test_certificate_signature_preferences = {
        .count = s2n_array_len(test_sig_scheme_list),
        .signature_schemes = test_sig_scheme_list,
    };

    const struct s2n_signature_scheme *const pss_sig_scheme_list[] = {
        &s2n_rsa_pss_pss_sha256,
        &s2n_rsa_pss_pss_sha384,
        &s2n_rsa_pss_pss_sha512,
        &s2n_rsa_pss_rsae_sha256,
        &s2n_rsa_pss_rsae_sha384,
        &s2n_rsa_pss_rsae_sha512,
    };

    const struct s2n_signature_preferences pss_certificate_signature_preferences = {
        .count = s2n_array_len(pss_sig_scheme_list),
        .signature_schemes = pss_sig_scheme_list,
    };

    /* s2n_is_certificate_sig_scheme_supported() */
    {
        struct s2n_connection *conn;
        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));

        /* Certificate signature algorithm is in test certificate signature preferences list */
        {
            EXPECT_SUCCESS(s2n_read_test_pem(S2N_ECDSA_P256_PKCS1_CERT_CHAIN, (char *) cert_file, S2N_MAX_TEST_PEM_SIZE));
            certLen = strlen((const char *) cert_file);

            /* Read the test certificates into an Openssl X509 struct */
            EXPECT_NOT_NULL(certBio = BIO_new(BIO_s_mem()));
            EXPECT_TRUE(BIO_write(certBio, cert_file, certLen) > 0);
            EXPECT_NOT_NULL(cert = PEM_read_bio_X509(certBio, NULL, NULL, NULL));

            EXPECT_OK(s2n_validate_sig_scheme_supported(conn, cert, &test_certificate_signature_preferences));

            EXPECT_SUCCESS(BIO_free(certBio));
            X509_free(cert);
        };

        /* Certificate signature algorithm is not in test certificate signature preferences list */
        {
            EXPECT_SUCCESS(s2n_read_test_pem(S2N_RSA_PSS_2048_SHA256_LEAF_CERT, (char *) cert_file, S2N_MAX_TEST_PEM_SIZE));
            certLen = strlen((const char *) cert_file);

            /* Read the test certificates into an Openssl X509 struct */
            EXPECT_NOT_NULL(certBio = BIO_new(BIO_s_mem()));
            EXPECT_TRUE(BIO_write(certBio, cert_file, certLen) > 0);
            EXPECT_NOT_NULL(cert = PEM_read_bio_X509(certBio, NULL, NULL, NULL));

            EXPECT_ERROR_WITH_ERRNO(s2n_validate_sig_scheme_supported(conn, cert, &test_certificate_signature_preferences), S2N_ERR_CERT_UNTRUSTED);

            EXPECT_SUCCESS(BIO_free(certBio));
            X509_free(cert);
        };

        /* Certificate signature algorithm is in the test certificate signature preferences list but signature is SHA-1
         * and TLS 1.3 has been negotiated.
         */
        {
            conn->actual_protocol_version = S2N_TLS13;
            EXPECT_SUCCESS(s2n_read_test_pem(S2N_RSA_2048_PKCS1_CERT_CHAIN, (char *) cert_file, S2N_MAX_TEST_PEM_SIZE));
            certLen = strlen((const char *) cert_file);

            /* Read the test certificates into an Openssl X509 struct */
            EXPECT_NOT_NULL(certBio = BIO_new(BIO_s_mem()));
            EXPECT_TRUE(BIO_write(certBio, cert_file, certLen) > 0);
            EXPECT_NOT_NULL(cert = PEM_read_bio_X509(certBio, NULL, NULL, NULL));

            EXPECT_ERROR_WITH_ERRNO(s2n_validate_sig_scheme_supported(conn, cert, &test_certificate_signature_preferences), S2N_ERR_CERT_UNTRUSTED);

            EXPECT_SUCCESS(BIO_free(certBio));
            X509_free(cert);
        };

        /* Certificate signature algorithm is in the test certificate signature preferences list and signature is SHA-1
         * and TLS 1.2 has been negotiated.
         */
        {
            conn->actual_protocol_version = S2N_TLS12;
            EXPECT_SUCCESS(s2n_read_test_pem(S2N_RSA_2048_PKCS1_CERT_CHAIN, (char *) cert_file, S2N_MAX_TEST_PEM_SIZE));
            certLen = strlen((const char *) cert_file);

            /* Read the test certificates into an Openssl X509 struct */
            EXPECT_NOT_NULL(certBio = BIO_new(BIO_s_mem()));
            EXPECT_TRUE(BIO_write(certBio, cert_file, certLen) > 0);
            EXPECT_NOT_NULL(cert = PEM_read_bio_X509(certBio, NULL, NULL, NULL));

            EXPECT_OK(s2n_validate_sig_scheme_supported(conn, cert, &test_certificate_signature_preferences));

            EXPECT_SUCCESS(BIO_free(certBio));
            X509_free(cert);
        };

        /* Certificates signed with an RSA PSS signature can be validated */
        {
            EXPECT_SUCCESS(s2n_read_test_pem(S2N_RSA_PSS_2048_SHA256_LEAF_CERT, (char *) cert_file, S2N_MAX_TEST_PEM_SIZE));
            certLen = strlen((const char *) cert_file);

            /* Read the test certificates into an Openssl X509 struct */
            EXPECT_NOT_NULL(certBio = BIO_new(BIO_s_mem()));
            EXPECT_TRUE(BIO_write(certBio, cert_file, certLen) > 0);
            EXPECT_NOT_NULL(cert = PEM_read_bio_X509(certBio, NULL, NULL, NULL));

            EXPECT_OK(s2n_validate_sig_scheme_supported(conn, cert, &pss_certificate_signature_preferences));

            EXPECT_SUCCESS(BIO_free(certBio));
            X509_free(cert);
        };

        EXPECT_SUCCESS(s2n_connection_free(conn));
    }

    /* s2n_validate_certificate_signature */
    {
        /* Connection using a security policy with no certificate_signature_preferences allows SHA-1 signatures in certificates */
        {
            struct s2n_connection *conn;
            struct s2n_config *config = s2n_config_new();

            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));
            /* 20140601 is a security policy with no certificate_signature_preferences list */
            EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, "20140601"));
            EXPECT_SUCCESS(s2n_connection_set_config(conn, config));

            EXPECT_SUCCESS(s2n_read_test_pem(S2N_RSA_2048_PKCS1_CERT_CHAIN, (char *) cert_file, S2N_MAX_TEST_PEM_SIZE));
            certLen = strlen((const char *) cert_file);

            /* Read the test certificates into an Openssl X509 struct */
            EXPECT_NOT_NULL(certBio = BIO_new(BIO_s_mem()));
            EXPECT_TRUE(BIO_write(certBio, cert_file, certLen) > 0);
            EXPECT_NOT_NULL(cert = PEM_read_bio_X509(certBio, NULL, NULL, NULL));

            EXPECT_OK(s2n_validate_certificate_signature(conn, cert));

            EXPECT_SUCCESS(s2n_config_free(config));
            EXPECT_SUCCESS(s2n_connection_free(conn));
            EXPECT_SUCCESS(BIO_free(certBio));
            X509_free(cert);
        };

        /* Connection using the default_tls13 security policy does not validate SHA-1 signatures in certificates */
        {
            struct s2n_connection *conn;
            struct s2n_config *config = s2n_config_new();

            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));
            EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, "default_tls13"));
            EXPECT_SUCCESS(s2n_connection_set_config(conn, config));

            EXPECT_SUCCESS(s2n_read_test_pem(S2N_RSA_2048_PKCS1_CERT_CHAIN, (char *) cert_file, S2N_MAX_TEST_PEM_SIZE));
            certLen = strlen((const char *) cert_file);

            /* Read the test certificates into an Openssl X509 struct */
            EXPECT_NOT_NULL(certBio = BIO_new(BIO_s_mem()));
            EXPECT_TRUE(BIO_write(certBio, cert_file, certLen) > 0);
            EXPECT_NOT_NULL(cert = PEM_read_bio_X509(certBio, NULL, NULL, NULL));

            EXPECT_ERROR_WITH_ERRNO(s2n_validate_certificate_signature(conn, cert), S2N_ERR_CERT_UNTRUSTED);

            EXPECT_SUCCESS(s2n_config_free(config));
            EXPECT_SUCCESS(s2n_connection_free(conn));
            EXPECT_SUCCESS(BIO_free(certBio));
            X509_free(cert);
        };

        /* Connection using the default_tls13 security policy ignores a SHA-1 signature on a root certificate */
        {
            struct s2n_connection *conn;
            struct s2n_config *config = s2n_config_new();

            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));
            EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, "default_tls13"));
            EXPECT_SUCCESS(s2n_connection_set_config(conn, config));

            EXPECT_SUCCESS(s2n_read_test_pem(S2N_SHA1_ROOT_SIGNATURE_CA_CERT, (char *) cert_file, S2N_MAX_TEST_PEM_SIZE));
            certLen = strlen((const char *) cert_file);

            /* Read the test certificates into an Openssl X509 struct */
            EXPECT_NOT_NULL(certBio = BIO_new(BIO_s_mem()));
            EXPECT_TRUE(BIO_write(certBio, cert_file, certLen) > 0);
            EXPECT_NOT_NULL(cert = PEM_read_bio_X509(certBio, NULL, NULL, NULL));

            EXPECT_OK(s2n_validate_certificate_signature(conn, cert));

            EXPECT_SUCCESS(s2n_config_free(config));
            EXPECT_SUCCESS(s2n_connection_free(conn));
            EXPECT_SUCCESS(BIO_free(certBio));
            X509_free(cert);
        };
    };
    END_TEST();
    return S2N_SUCCESS;
}
