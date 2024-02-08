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
#include "tls/s2n_security_policies.h"
#include "tls/s2n_signature_scheme.h"

int main(int argc, char **argv)
{
    BEGIN_TEST();

    const struct s2n_signature_scheme *const test_sig_scheme_list[] = {
        &s2n_ecdsa_sha256,
        &s2n_rsa_pkcs1_sha1,
    };

    const struct s2n_signature_preferences test_certificate_signature_preferences = {
        .count = s2n_array_len(test_sig_scheme_list),
        .signature_schemes = test_sig_scheme_list,
    };

    const struct s2n_security_policy test_sp = {
        .certificate_signature_preferences = &test_certificate_signature_preferences,
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

            EXPECT_OK(s2n_security_policy_validate_cert_signature(&test_sp, &info));
        };

        /* Certificate signature algorithm is not in test certificate signature preferences list */
        {
            struct s2n_cert_info info = {
                .self_signed = false,
                .signature_digest_nid = NID_undef,
                .signature_nid = NID_rsassaPss,
            };

            EXPECT_ERROR_WITH_ERRNO(
                    s2n_security_policy_validate_cert_signature(&test_sp, &info),
                    S2N_ERR_SECURITY_POLICY_INCOMPATIBLE_CERT);
        };

        /* Certificates signed with an RSA PSS signature can be validated */
        {
            struct s2n_cert_info info = {
                .self_signed = false,
                .signature_digest_nid = NID_undef,
                .signature_nid = NID_rsassaPss,
            };

            EXPECT_OK(s2n_security_policy_validate_cert_signature(&test_pss_sp, &info));
        };
    };

    /* s2n_security_policy_validate_certificate_chain */
    {
        int valid_sig_nid = s2n_ecdsa_sha256.libcrypto_nid;
        int valid_hash_nid = 0;
        EXPECT_SUCCESS(s2n_hash_NID_type(s2n_ecdsa_sha256.hash_alg, &valid_hash_nid));

        int invalid_sig_nid = s2n_rsa_pkcs1_sha256.libcrypto_nid;
        int invalid_hash_nid = 0;
        EXPECT_SUCCESS(s2n_hash_NID_type(s2n_rsa_pkcs1_sha256.hash_alg, &valid_hash_nid));

        struct s2n_cert_info valid = {
            .self_signed = false,
            .signature_nid = valid_sig_nid,
            .signature_digest_nid = valid_hash_nid,
        };
        struct s2n_cert root = { 0 };
        root.info = valid;
        root.info.self_signed = true;

        struct s2n_cert intermediate = { 0 };
        intermediate.info = valid;
        intermediate.next = &root;

        struct s2n_cert leaf = { 0 };
        leaf.info = valid;
        leaf.next = &intermediate;

        struct s2n_cert_chain cert_chain = { 0 };
        cert_chain.head = &leaf;

        struct s2n_cert_chain_and_key chain = { 0 };
        chain.cert_chain = &cert_chain;
        /* valid chain */
        {
            EXPECT_OK(s2n_security_policy_validate_certificate_chain(&test_sp, &chain));
        };

        /* an invalid root signature is ignored */
        {
            root.info.signature_nid = invalid_sig_nid;
            root.info.signature_digest_nid = invalid_sig_nid;
            EXPECT_OK(s2n_security_policy_validate_certificate_chain(&test_sp, &chain));
        };

        /* an invalid intermediate causes a failure */
        {
            intermediate.info.signature_nid = invalid_sig_nid;
            intermediate.info.signature_digest_nid = invalid_sig_nid;
            EXPECT_ERROR_WITH_ERRNO(s2n_security_policy_validate_certificate_chain(&test_sp, &chain), S2N_ERR_SECURITY_POLICY_INCOMPATIBLE_CERT);
        }
    };

    DEFER_CLEANUP(struct s2n_cert_chain_and_key *cert = NULL, s2n_cert_chain_and_key_ptr_free);
    EXPECT_SUCCESS(
            s2n_test_cert_permutation_load_server_chain(&cert, "ec", "ecdsa", "p384", "sha256"));
    /* s2n_config cases  */
    {
        /* configure security policy then load an invalid cert */
        {
            DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
            EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, "rfc9151"));

            EXPECT_FAILURE_WITH_ERRNO(s2n_config_add_cert_chain_and_key_to_store(config, cert), S2N_ERR_SECURITY_POLICY_INCOMPATIBLE_CERT);

            /* assert that no certs were loaded */
            uint32_t domain_certs = 0;
            EXPECT_EQUAL(s2n_config_get_num_default_certs(config), 0);
            EXPECT_SUCCESS(s2n_map_size(config->domain_name_to_cert_map, &domain_certs));
            EXPECT_EQUAL(domain_certs, 0);
            EXPECT_EQUAL(s2n_config_get_num_default_certs(config), 0);
        };

        /* load a cert then configure an invalid security policy */
        {
            DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
            EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, cert));
            const struct s2n_security_policy *default_sp = config->security_policy;
            EXPECT_FAILURE_WITH_ERRNO(s2n_config_set_cipher_preferences(config, "rfc9151"), S2N_ERR_SECURITY_POLICY_INCOMPATIBLE_CERT);

            /* assert that the security policy was not changed */
            EXPECT_EQUAL(config->security_policy, default_sp);
        };
    };

    /* s2n_connection cases */
    {
        /* setup a config with the default security policy and the test cert */
        DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, cert));

        /* set a config then set an invalid security policy override */
        {
            DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            EXPECT_SUCCESS(s2n_connection_set_config(conn, config));
            EXPECT_FAILURE_WITH_ERRNO(s2n_connection_set_cipher_preferences(conn, "rfc9151"), S2N_ERR_SECURITY_POLICY_INCOMPATIBLE_CERT);

            /* assert that the security policy override was not successful */
            EXPECT_NULL(conn->security_policy_override);
        };
        /* set a security_policy_override then set an invalid config */
        {
            DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(conn, "rfc9151"));
            struct s2n_config *default_config = conn->config;
            EXPECT_FAILURE_WITH_ERRNO(s2n_connection_set_config(conn, config), S2N_ERR_SECURITY_POLICY_INCOMPATIBLE_CERT);

            /* assert that the config was not changed */
            EXPECT_EQUAL(conn->config, default_config);
        };
    };

    /* certificate_signature_preferences_apply_locally behavior tests */
    {
        /* for this test we need a security policy that doesn't apply cert preferences locally */
        const struct s2n_security_policy *non_local_sp = &security_policy_default_fips;
        EXPECT_FALSE(non_local_sp->certificate_preferences_apply_locally);

        DEFER_CLEANUP(struct s2n_cert_chain_and_key *cert = NULL, s2n_cert_chain_and_key_ptr_free);
        EXPECT_SUCCESS(s2n_test_cert_permutation_load_server_chain(&cert, "rsae", "pss", "4096",
                "sha384"));

        /* confirm that the cert does not respect certificate signature preferences */
        EXPECT_ERROR(s2n_security_policy_validate_certificate_chain(non_local_sp, cert));

        /* security policy can be set on a non-compliant config */
        {
            DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
            EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, cert));
            EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, "default_fips"));
        };

        /* non-compliant certs can be loaded into a config */
        {
            DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
            EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, "default_fips"));
            EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, cert));
        };

        /* security policy can be set on a non-compliant connection */
        {
            DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
            EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, cert));

            EXPECT_SUCCESS(s2n_connection_set_config(conn, config));
            EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(conn, "default_fips"));
        };

        /* non-compliant certs can still be used with a connection policy override */
        {
            DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
            EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, cert));

            EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(conn, "default_fips"));
            EXPECT_SUCCESS(s2n_connection_set_config(conn, config));
        };
    };

    END_TEST();
    return S2N_SUCCESS;
}
