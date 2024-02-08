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
                    S2N_ERR_CERT_UNTRUSTED);
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

    END_TEST();
    return S2N_SUCCESS;
}
