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
#include "tls/s2n_certificate_keys.h"
#include "tls/s2n_security_policies.h"
#include "tls/s2n_signature_scheme.h"

#define CHAIN_LENGTH 3

static S2N_RESULT s2n_test_construct_cert_chain(
        struct s2n_cert *certs,
        size_t certs_length,
        struct s2n_cert_chain *cert_chain,
        struct s2n_cert_chain_and_key *chain,
        const struct s2n_cert_info *valid_info)
{
    RESULT_ENSURE_REF(certs);
    RESULT_ENSURE_REF(cert_chain);
    RESULT_ENSURE_REF(chain);
    RESULT_ENSURE_REF(valid_info);

    for (size_t i = 0; i < certs_length; i++) {
        certs[i].info = *valid_info;
        if (i != certs_length - 1) {
            certs[i].next = &certs[i + 1];
        }
    }

    /* root cert */
    certs[certs_length - 1].info.self_signed = true;

    cert_chain->head = &certs[0];
    chain->cert_chain = cert_chain;

    return S2N_RESULT_OK;
}

int main(int argc, char **argv)
{
    BEGIN_TEST();

    const int valid_sig_nid = NID_ecdsa_with_SHA256;
    const int valid_hash_nid = NID_sha256;
    const int valid_key_size = 384;
    const int valid_key_nid = NID_secp384r1;

    const int invalid_sig_nid = NID_sha256WithRSAEncryption;
    const int invalid_hash_nid = NID_sha1;
    const int invalid_key_size = 256;
    const int invalid_key_nid = NID_X9_62_prime256v1;

    const struct s2n_cert_info valid_info = {
        .self_signed = false,
        .signature_nid = valid_sig_nid,
        .signature_digest_nid = valid_hash_nid,
        .public_key_bits = valid_key_size,
        .public_key_nid = valid_key_nid,
    };

    const struct s2n_signature_scheme *const test_sig_scheme_list[] = {
        &s2n_ecdsa_sha256,
        &s2n_rsa_pkcs1_sha1,
    };

    const struct s2n_certificate_key *const test_cert_key_list[] = {
        &s2n_ec_p384,
        &s2n_rsa_rsae_3072,
    };

    const struct s2n_signature_preferences test_certificate_signature_preferences = {
        .count = s2n_array_len(test_sig_scheme_list),
        .signature_schemes = test_sig_scheme_list,
    };

    const struct s2n_certificate_key_preferences test_cert_key_preferences = {
        .count = s2n_array_len(test_cert_key_list),
        .certificate_keys = test_cert_key_list,
    };

    const struct s2n_security_policy test_sp = {
        .certificate_signature_preferences = &test_certificate_signature_preferences,
        .certificate_key_preferences = &test_cert_key_preferences,
        .certificate_preferences_apply_locally = true,
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

    const struct s2n_security_policy test_pss_sp = {
        .certificate_signature_preferences = &pss_certificate_signature_preferences,
    };

    /* s2n_security_policy_validate_cert_signature() */
    {
        /* Certificate signature algorithm is in test certificate signature preferences list */
        {
            struct s2n_cert_info info = {
                .self_signed = false,
                .signature_digest_nid = NID_sha256,
                .signature_nid = NID_ecdsa_with_SHA256,
            };

            EXPECT_OK(s2n_security_policy_validate_cert_signature(&test_sp, &info,
                    S2N_ERR_SECURITY_POLICY_INCOMPATIBLE_CERT));
        };

        /* Certificate signature algorithm is not in test certificate signature preferences list */
        {
            struct s2n_cert_info info = {
                .self_signed = false,
                .signature_digest_nid = NID_undef,
                .signature_nid = NID_rsassaPss,
            };

            EXPECT_ERROR_WITH_ERRNO(s2n_security_policy_validate_cert_signature(&test_sp, &info,
                                            S2N_ERR_SECURITY_POLICY_INCOMPATIBLE_CERT),
                    S2N_ERR_SECURITY_POLICY_INCOMPATIBLE_CERT);
        };

        /* Certificates signed with an RSA PSS signature can be validated */
        {
            struct s2n_cert_info info = {
                .self_signed = false,
                .signature_digest_nid = NID_undef,
                .signature_nid = NID_rsassaPss,
            };

            EXPECT_OK(s2n_security_policy_validate_cert_signature(&test_pss_sp, &info,
                    S2N_ERR_SECURITY_POLICY_INCOMPATIBLE_CERT));
        };
    };

    /* s2n_security_policy_validate_cert_key() */
    {
        /* Certificate key is in test certificate key list */
        {
            struct s2n_cert_info info = {
                .public_key_nid = valid_key_nid,
                .public_key_bits = valid_key_size,
            };

            EXPECT_OK(s2n_security_policy_validate_cert_key(&test_sp, &info,
                    S2N_ERR_SECURITY_POLICY_INCOMPATIBLE_CERT));
        };

        /* Certificate key is not in test certificate key list */
        {
            struct s2n_cert_info info = {
                .public_key_nid = invalid_key_nid,
                .signature_nid = invalid_key_size,
            };

            EXPECT_ERROR_WITH_ERRNO(s2n_security_policy_validate_cert_key(&test_sp, &info,
                                            S2N_ERR_SECURITY_POLICY_INCOMPATIBLE_CERT),
                    S2N_ERR_SECURITY_POLICY_INCOMPATIBLE_CERT);
        };
    };

    /* s2n_security_policy_validate_certificate_chain() */
    {
        /* a valid certificate chain passes validation */
        {
            struct s2n_cert certs[CHAIN_LENGTH] = { 0 };
            struct s2n_cert_chain cert_chain = { 0 };
            struct s2n_cert_chain_and_key chain = { 0 };
            EXPECT_OK(s2n_test_construct_cert_chain(certs, CHAIN_LENGTH, &cert_chain, &chain, &valid_info));
            EXPECT_OK(s2n_security_policy_validate_certificate_chain(&test_sp, &chain));
        };

        /* test that failures can be detected for any cert in the chain */
        for (size_t i = 0; i < CHAIN_LENGTH; i++) {
            /* an invalid signature causes a failure */
            {
                struct s2n_cert certs[CHAIN_LENGTH] = { 0 };
                struct s2n_cert_chain cert_chain = { 0 };
                struct s2n_cert_chain_and_key chain = { 0 };
                EXPECT_OK(s2n_test_construct_cert_chain(certs, CHAIN_LENGTH, &cert_chain, &chain, &valid_info));
                certs[i].info.signature_nid = invalid_sig_nid;
                certs[i].info.signature_digest_nid = invalid_hash_nid;
                EXPECT_ERROR_WITH_ERRNO(s2n_security_policy_validate_certificate_chain(&test_sp, &chain),
                        S2N_ERR_SECURITY_POLICY_INCOMPATIBLE_CERT);
            };

            /* an invalid key nid causes a failure */
            {
                struct s2n_cert certs[CHAIN_LENGTH] = { 0 };
                struct s2n_cert_chain cert_chain = { 0 };
                struct s2n_cert_chain_and_key chain = { 0 };
                EXPECT_OK(s2n_test_construct_cert_chain(certs, CHAIN_LENGTH, &cert_chain, &chain, &valid_info));
                certs[i].info.public_key_nid = invalid_key_nid;
                EXPECT_ERROR_WITH_ERRNO(s2n_security_policy_validate_certificate_chain(&test_sp, &chain),
                        S2N_ERR_SECURITY_POLICY_INCOMPATIBLE_CERT);
            };

            /* an invalid key size causes a failure */
            {
                struct s2n_cert certs[CHAIN_LENGTH] = { 0 };
                struct s2n_cert_chain cert_chain = { 0 };
                struct s2n_cert_chain_and_key chain = { 0 };
                EXPECT_OK(s2n_test_construct_cert_chain(certs, CHAIN_LENGTH, &cert_chain, &chain, &valid_info));
                certs[i].info.public_key_bits = invalid_key_size;
                EXPECT_ERROR_WITH_ERRNO(s2n_security_policy_validate_certificate_chain(&test_sp, &chain),
                        S2N_ERR_SECURITY_POLICY_INCOMPATIBLE_CERT);
            };

            /* when certificate_preferences_apply_locally is false then validation succeeds */
            {
                struct s2n_cert certs[CHAIN_LENGTH] = { 0 };
                struct s2n_cert_chain cert_chain = { 0 };
                struct s2n_cert_chain_and_key chain = { 0 };
                EXPECT_OK(s2n_test_construct_cert_chain(certs, CHAIN_LENGTH, &cert_chain, &chain, &valid_info));

                struct s2n_security_policy test_sp_no_local = test_sp;
                test_sp_no_local.certificate_preferences_apply_locally = false;

                certs[i].info.signature_nid = invalid_sig_nid;
                certs[i].info.public_key_nid = invalid_key_nid;
                EXPECT_OK(s2n_security_policy_validate_certificate_chain(&test_sp_no_local, &chain));
            };
        }
    };

    /* s2n_connection_set_cipher_preferences */
    {
        DEFER_CLEANUP(struct s2n_cert_chain_and_key *invalid_cert = NULL, s2n_cert_chain_and_key_ptr_free);
        EXPECT_SUCCESS(s2n_test_cert_permutation_load_server_chain(&invalid_cert, "rsae", "pss", "4096", "sha384"));

        /* when certificate preferences apply locally and the connection contains
         * an invalid config then s2n_connection_set_cipher_preferences fails
         */
        {
            DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
            EXPECT_NOT_NULL(config);
            DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_SERVER), s2n_connection_ptr_free);
            EXPECT_NOT_NULL(conn);
            EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, invalid_cert));
            EXPECT_SUCCESS(s2n_connection_set_config(conn, config));
            EXPECT_FAILURE_WITH_ERRNO(s2n_connection_set_cipher_preferences(conn, "rfc9151"),
                    S2N_ERR_SECURITY_POLICY_INCOMPATIBLE_CERT);
        }
    };

    END_TEST();
    return S2N_SUCCESS;
}
