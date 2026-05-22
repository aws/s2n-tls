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

#include <openssl/pem.h>
#include <openssl/x509.h>

#include "crypto/s2n_rsa_pss.h"
#include "s2n_test.h"
#include "testlib/s2n_testlib.h"

S2N_RESULT s2n_x509_validator_read_asn1_cert(struct s2n_stuffer *cert_chain_in_stuffer,
        struct s2n_blob *asn1_cert);

static S2N_RESULT s2n_test_assert_s2n_cert_info_equality(const struct s2n_cert_info *info_a,
        const struct s2n_cert_info *info_b)
{
    RESULT_ENSURE_EQ(info_a->public_key_bits, info_b->public_key_bits);
    RESULT_ENSURE_EQ(info_a->public_key_nid, info_b->public_key_nid);
    RESULT_ENSURE_EQ(info_a->signature_nid, info_b->signature_nid);
    RESULT_ENSURE_EQ(info_a->signature_digest_nid, info_b->signature_digest_nid);
    RESULT_ENSURE_EQ(info_a->self_signed, info_b->self_signed);
    return S2N_RESULT_OK;
}

int main(int argc, char **argv)
{
    BEGIN_TEST();

    /* A certificate with one trailing byte is parsed successfully */
    {
        uint8_t cert_chain_data[S2N_MAX_TEST_PEM_SIZE] = { 0 };
        uint32_t cert_chain_len = 0;
        EXPECT_SUCCESS(s2n_read_test_pem_and_len(S2N_ONE_TRAILING_BYTE_CERT_BIN, cert_chain_data,
                &cert_chain_len, S2N_MAX_TEST_PEM_SIZE));

        struct s2n_blob cert_chain_blob = { 0 };
        EXPECT_SUCCESS(s2n_blob_init(&cert_chain_blob, cert_chain_data, cert_chain_len));

        DEFER_CLEANUP(struct s2n_stuffer cert_chain_stuffer = { 0 }, s2n_stuffer_free);
        EXPECT_SUCCESS(s2n_stuffer_init_written(&cert_chain_stuffer, &cert_chain_blob));

        struct s2n_blob cert_asn1_der = { 0 };
        EXPECT_OK(s2n_x509_validator_read_asn1_cert(&cert_chain_stuffer, &cert_asn1_der));

        {
            DEFER_CLEANUP(X509 *cert = NULL, X509_free_pointer);
            EXPECT_OK(s2n_openssl_x509_parse(&cert_asn1_der, &cert));
        }
        {
            DEFER_CLEANUP(X509 *cert = NULL, X509_free_pointer);
            EXPECT_OK(s2n_openssl_x509_parse_without_length_validation(&cert_asn1_der, &cert));
        }
    }

    /* A certificate with too many trailing bytes errors */
    {
        uint8_t cert_chain_data[S2N_MAX_TEST_PEM_SIZE] = { 0 };
        uint32_t cert_chain_len = 0;
        EXPECT_SUCCESS(s2n_read_test_pem_and_len(S2N_FOUR_TRAILING_BYTE_CERT_BIN, cert_chain_data,
                &cert_chain_len, S2N_MAX_TEST_PEM_SIZE));

        struct s2n_blob cert_chain_blob = { 0 };
        EXPECT_SUCCESS(s2n_blob_init(&cert_chain_blob, cert_chain_data, cert_chain_len));

        DEFER_CLEANUP(struct s2n_stuffer cert_chain_stuffer = { 0 }, s2n_stuffer_free);
        EXPECT_SUCCESS(s2n_stuffer_init_written(&cert_chain_stuffer, &cert_chain_blob));

        struct s2n_blob cert_asn1_der = { 0 };
        EXPECT_OK(s2n_x509_validator_read_asn1_cert(&cert_chain_stuffer, &cert_asn1_der));

        {
            DEFER_CLEANUP(X509 *cert = NULL, X509_free_pointer);
            EXPECT_ERROR(s2n_openssl_x509_parse(&cert_asn1_der, &cert));
        }
        {
            DEFER_CLEANUP(X509 *cert = NULL, X509_free_pointer);
            EXPECT_OK(s2n_openssl_x509_parse_without_length_validation(&cert_asn1_der, &cert));
        }
    }

    /* s2n_openssl_x509_get_cert_info */
    struct {
        const char *key_type;
        const char *signature;
        const char *key_size;
        const char *digest;
        int expected_signature_nid;
        int expected_digest_nid;
        int expected_public_key_nid;
        int expected_public_key_bits;
    } test_cases[] = {
        {
                .key_type = "ec",
                .signature = "ecdsa",
                .key_size = "p384",
                .digest = "sha256",
                .expected_signature_nid = NID_ecdsa_with_SHA256,
                .expected_digest_nid = NID_sha256,
                .expected_public_key_nid = NID_secp384r1,
                .expected_public_key_bits = 384,
        },
        {
                .key_type = "ec",
                .signature = "ecdsa",
                .key_size = "p256",
                .digest = "sha384",
                .expected_signature_nid = NID_ecdsa_with_SHA384,
                .expected_digest_nid = NID_sha384,
                .expected_public_key_nid = NID_X9_62_prime256v1,
                .expected_public_key_bits = 256,
        },
        {
                .key_type = "ec",
                .signature = "ecdsa",
                .key_size = "p521",
                .digest = "sha512",
                .expected_signature_nid = NID_ecdsa_with_SHA512,
                .expected_digest_nid = NID_sha512,
                .expected_public_key_nid = NID_secp521r1,
                .expected_public_key_bits = 521,
        },
        {
                .key_type = "rsae",
                .signature = "pkcs",
                .key_size = "2048",
                .digest = "sha1",
                .expected_signature_nid = NID_sha1WithRSAEncryption,
                .expected_digest_nid = NID_sha1,
                .expected_public_key_nid = NID_rsaEncryption,
                .expected_public_key_bits = 2048,
        },
        {
                .key_type = "rsae",
                .signature = "pkcs",
                .key_size = "2048",
                .digest = "sha224",
                .expected_signature_nid = NID_sha224WithRSAEncryption,
                .expected_digest_nid = NID_sha224,
                .expected_public_key_nid = NID_rsaEncryption,
                .expected_public_key_bits = 2048,
        },
        {
                .key_type = "rsae",
                .signature = "pkcs",
                .key_size = "3072",
                .digest = "sha384",
                .expected_signature_nid = NID_sha384WithRSAEncryption,
                .expected_digest_nid = NID_sha384,
                .expected_public_key_nid = NID_rsaEncryption,
                .expected_public_key_bits = 3072,
        },
#if RSA_PSS_CERTS_SUPPORTED
        {
                .key_type = "rsae",
                .signature = "pss",
                .key_size = "4096",
                .digest = "sha384",
                .expected_signature_nid = NID_rsassaPss,
                .expected_digest_nid = NID_undef,
                .expected_public_key_nid = NID_rsaEncryption,
                .expected_public_key_bits = 4096,
        },
        {
                .key_type = "rsapss",
                .signature = "pss",
                .key_size = "2048",
                .digest = "sha256",
                .expected_signature_nid = NID_rsassaPss,
                .expected_digest_nid = NID_undef,
                .expected_public_key_nid = NID_rsassaPss,
                .expected_public_key_bits = 2048,
        },
#endif
    };

    for (size_t i = 0; i < s2n_array_len(test_cases); i++) {
        /* initialize variables and read in certificates */
        char pathbuffer[S2N_MAX_TEST_PEM_PATH_LENGTH] = { 0 };
        uint8_t cert_file[S2N_MAX_TEST_PEM_SIZE] = { 0 };
        EXPECT_OK(s2n_test_cert_permutation_get_server_chain_path(&pathbuffer[0],
                test_cases[i].key_type, test_cases[i].signature, test_cases[i].key_size,
                test_cases[i].digest));
        EXPECT_SUCCESS(s2n_read_test_pem(pathbuffer, (char *) cert_file, S2N_MAX_TEST_PEM_SIZE));

        DEFER_CLEANUP(X509 *leaf = NULL, X509_free_pointer);
        DEFER_CLEANUP(X509 *intermediate = NULL, X509_free_pointer);
        DEFER_CLEANUP(X509 *root = NULL, X509_free_pointer);

        /* read in cert chain */
        size_t chain_len = strlen((const char *) cert_file);
        BIO *cert_bio = NULL;
        EXPECT_NOT_NULL(cert_bio = BIO_new(BIO_s_mem()));
        EXPECT_TRUE(BIO_write(cert_bio, cert_file, chain_len) > 0);
        EXPECT_NOT_NULL(leaf = PEM_read_bio_X509(cert_bio, NULL, NULL, NULL));
        EXPECT_NOT_NULL(intermediate = PEM_read_bio_X509(cert_bio, NULL, NULL, NULL));
        EXPECT_NOT_NULL(root = PEM_read_bio_X509(cert_bio, NULL, NULL, NULL));
        EXPECT_SUCCESS(BIO_free(cert_bio));

        /* retrieve cert info from test case certificates */
        struct s2n_cert_info leaf_info = { 0 };
        struct s2n_cert_info intermediate_info = { 0 };
        struct s2n_cert_info root_info = { 0 };

        EXPECT_OK(s2n_openssl_x509_get_cert_info(leaf, &leaf_info));
        EXPECT_OK(s2n_openssl_x509_get_cert_info(intermediate, &intermediate_info));
        EXPECT_OK(s2n_openssl_x509_get_cert_info(root, &root_info));

        struct s2n_cert_info expected_info = {
            .signature_nid = test_cases[i].expected_signature_nid,
            .signature_digest_nid = test_cases[i].expected_digest_nid,
            .public_key_nid = test_cases[i].expected_public_key_nid,
            .public_key_bits = test_cases[i].expected_public_key_bits,
            .self_signed = false,
        };

        /* assert that cert info matches expected values */
        EXPECT_OK(s2n_test_assert_s2n_cert_info_equality(&leaf_info, &expected_info));
        EXPECT_OK(s2n_test_assert_s2n_cert_info_equality(&intermediate_info, &expected_info));
        /* root should be self-signed, but otherwise equal */
        expected_info.self_signed = true;
        EXPECT_OK(s2n_test_assert_s2n_cert_info_equality(&root_info, &expected_info));
    }

    END_TEST();
}
