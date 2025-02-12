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

#include "tls/s2n_signature_scheme.c"

#include "s2n_test.h"

int main(int argc, char **argv)
{
    BEGIN_TEST();

    const struct s2n_signature_preferences *all_prefs = &s2n_signature_preferences_all;

    /* Test all signature schemes */
    size_t policy_i = 0;
    while (security_policy_selection[policy_i].version != NULL) {
        const struct s2n_signature_preferences *sig_prefs =
                security_policy_selection[policy_i].security_policy->signature_preferences;
        for (size_t sig_i = 0; sig_i < sig_prefs->count; sig_i++) {
            const struct s2n_signature_scheme *const sig_scheme = sig_prefs->signature_schemes[sig_i];

            EXPECT_NOT_EQUAL(sig_scheme->iana_value, 0);
            EXPECT_NOT_EQUAL(sig_scheme->hash_alg, S2N_HASH_NONE);
            EXPECT_NOT_EQUAL(sig_scheme->sig_alg, S2N_SIGNATURE_ANONYMOUS);
            EXPECT_NOT_EQUAL(sig_scheme->libcrypto_nid, 0);

            if (sig_scheme->sig_alg == S2N_SIGNATURE_ECDSA
                    && sig_scheme->maximum_protocol_version != S2N_TLS12) {
                EXPECT_NOT_NULL(sig_scheme->signature_curve);
            } else {
                EXPECT_NULL(sig_scheme->signature_curve);
            }

            /* No duplicate signature schemes are allowed */
            for (size_t dup_i = 0; dup_i < sig_prefs->count; dup_i++) {
                if (dup_i == sig_i) {
                    continue;
                }
                const struct s2n_signature_scheme *const potential_duplicate =
                        sig_prefs->signature_schemes[dup_i];
                EXPECT_NOT_EQUAL(sig_scheme->iana_value, potential_duplicate->iana_value);
            }

            /* Must be included in s2n_signature_preferences_all */
            bool in_all = false;
            for (size_t all_i = 0; all_i < all_prefs->count; all_i++) {
                if (sig_scheme == all_prefs->signature_schemes[all_i]) {
                    in_all = true;
                }
            }
            EXPECT_TRUE(in_all);
        }
        policy_i++;
    }

    /* Test: s2n_signature_preferences_all should also include s2n_rsa_pkcs1_md5_sha1
     *
     * s2n_rsa_pkcs1_md5_sha1 is the implicit default for pre-TLS1.2 when no signature
     * schemes are provided. Any code that needs to handle "all signature schemes"
     * also needs to handle s2n_rsa_pkcs1_md5_sha1. It is not explicitly included
     * in any security policy, but should still be tracked by s2n_signature_preferences_all.
     */
    {
        bool includes_md5_sha1 = false;
        for (size_t i = 0; i < all_prefs->count; i++) {
            if (all_prefs->signature_schemes[i] == &s2n_rsa_pkcs1_md5_sha1) {
                includes_md5_sha1 = true;
            }
        }
        EXPECT_TRUE(includes_md5_sha1);
    }

    /* Test: s2n_signature_preferences_all should not include s2n_null_sig_scheme.
     *
     * s2n_null_sig_scheme is not a real signature scheme and is just a placeholder.
     */
    {
        bool includes_null = false;
        for (size_t i = 0; i < all_prefs->count; i++) {
            if (all_prefs->signature_schemes[i] == &s2n_null_sig_scheme) {
                includes_null = true;
            }
        }
        EXPECT_FALSE(includes_null);
    }

    END_TEST();
}
