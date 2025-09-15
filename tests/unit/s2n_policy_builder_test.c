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

#include <fcntl.h>
#include <string.h>
#include <unistd.h>

#include "s2n_test.h"
#include "testlib/s2n_testlib.h"
#include "tls/policy/s2n_policy_feature.h"

static S2N_RESULT s2n_security_policies_assert_match(
        const struct s2n_security_policy *a, const struct s2n_security_policy *b)
{
    /* Compare cipher preferences */
    const struct s2n_cipher_preferences *a_cipher_prefs = a->cipher_preferences;
    const struct s2n_cipher_preferences *b_cipher_prefs = b->cipher_preferences;
    EXPECT_NOT_NULL(a_cipher_prefs);
    EXPECT_NOT_NULL(b_cipher_prefs);
    EXPECT_EQUAL(a_cipher_prefs->count, b_cipher_prefs->count);
    for (size_t i = 0; i < a_cipher_prefs->count; i++) {
        EXPECT_EQUAL(a_cipher_prefs->suites[i], b_cipher_prefs->suites[i]);
    }

    /* Compare signature preferences */
    const struct s2n_signature_preferences *a_sig_prefs = a->signature_preferences;
    const struct s2n_signature_preferences *b_sig_prefs = b->signature_preferences;
    EXPECT_NOT_NULL(a_sig_prefs);
    EXPECT_NOT_NULL(b_sig_prefs);
    EXPECT_EQUAL(a_sig_prefs->count, b_sig_prefs->count);
    for (size_t i = 0; i < a_sig_prefs->count; i++) {
        EXPECT_EQUAL(a_sig_prefs->signature_schemes[i], b_sig_prefs->signature_schemes[i]);
    }

    /* Compare certificate signature preferences */
    const struct s2n_signature_preferences *a_cert_sig_prefs = a->certificate_signature_preferences;
    const struct s2n_signature_preferences *b_cert_sig_prefs = b->certificate_signature_preferences;
    if (a_cert_sig_prefs) {
        EXPECT_NOT_NULL(b_cert_sig_prefs);
        EXPECT_EQUAL(a_cert_sig_prefs->count, b_cert_sig_prefs->count);
        for (size_t i = 0; i < a_cert_sig_prefs->count; i++) {
            EXPECT_EQUAL(a_cert_sig_prefs->signature_schemes[i], b_cert_sig_prefs->signature_schemes[i]);
        }
    } else {
        EXPECT_NULL(b_cert_sig_prefs);
    }

    /* Compare ecc curve preferences */
    const struct s2n_ecc_preferences *a_ecc_prefs = a->ecc_preferences;
    const struct s2n_ecc_preferences *b_ecc_prefs = b->ecc_preferences;
    EXPECT_NOT_NULL(a_ecc_prefs);
    EXPECT_NOT_NULL(b_ecc_prefs);
    EXPECT_EQUAL(a_ecc_prefs->count, b_ecc_prefs->count);
    for (size_t i = 0; i < a_ecc_prefs->count; i++) {
        EXPECT_EQUAL(a_ecc_prefs->ecc_curves[i], b_ecc_prefs->ecc_curves[i]);
    }

    /* Compare certificate key preferences */
    const struct s2n_certificate_key_preferences *a_key_prefs = a->certificate_key_preferences;
    const struct s2n_certificate_key_preferences *b_key_prefs = b->certificate_key_preferences;
    if (a_key_prefs) {
        EXPECT_NOT_NULL(b_key_prefs);
        EXPECT_EQUAL(a_key_prefs->count, b_key_prefs->count);
        for (size_t i = 0; i < a_key_prefs->count; i++) {
            EXPECT_EQUAL(a_key_prefs->certificate_keys[i], b_key_prefs->certificate_keys[i]);
        }
    } else {
        EXPECT_NULL(b_key_prefs);
    }

    /* Compare kem preferences */
    const struct s2n_kem_preferences *a_kem_prefs = a->kem_preferences;
    const struct s2n_kem_preferences *b_kem_prefs = b->kem_preferences;
    if (a_kem_prefs) {
        EXPECT_NOT_NULL(b_kem_prefs);
        EXPECT_EQUAL(a_kem_prefs->tls13_kem_group_count, b_kem_prefs->tls13_kem_group_count);
        for (size_t i = 0; i < a_kem_prefs->tls13_kem_group_count; i++) {
            EXPECT_EQUAL(a_kem_prefs->tls13_kem_groups[i], b_kem_prefs->tls13_kem_groups[i]);
        }
    } else {
        EXPECT_NULL(b_kem_prefs);
    }

    /* If we assume that the source code uses memcpy or similar instead of
     * setting individual fields, we don't have to ensure that EVERY field matches.
     * Checking a few fields should be sufficient.
     * That means that this test does not need to be updated with all new fields.
     * We should include one field from each preferences list, but the `count`
     * checks above should also handle that requirement.
     */
    EXPECT_EQUAL(a->minimum_protocol_version, b->minimum_protocol_version);
    EXPECT_EQUAL(a->rules[S2N_PERFECT_FORWARD_SECRECY], b->rules[S2N_PERFECT_FORWARD_SECRECY]);
    EXPECT_EQUAL(a_cipher_prefs->allow_chacha20_boosting, b_cipher_prefs->allow_chacha20_boosting);
    if (a_kem_prefs) {
        EXPECT_EQUAL(a_kem_prefs->tls13_pq_hybrid_draft_revision, b_kem_prefs->tls13_pq_hybrid_draft_revision);
    }

    return S2N_RESULT_OK;
}

int main(int argc, char **argv)
{
    BEGIN_TEST();

    /* Test: s2n_security_policy_builder_from_version / s2n_security_policy_builder_free */
    {
        /* Test: safety */
        {
            EXPECT_NULL_WITH_ERRNO(
                    s2n_security_policy_builder_from_version(NULL),
                    S2N_ERR_INVALID_ARGUMENT);
            EXPECT_SUCCESS(s2n_security_policy_builder_free(NULL));
            struct s2n_security_policy_builder *builder = NULL;
            EXPECT_SUCCESS(s2n_security_policy_builder_free(&builder));
        };

        /* Test: builder from invalid policy version */
        {
            EXPECT_NULL_WITH_ERRNO(
                    s2n_security_policy_builder_from_version("not_a_real_policy_version"),
                    S2N_ERR_INVALID_SECURITY_POLICY);
        };

        /* Test: successfully create and free a builder */
        {
            struct s2n_security_policy_builder *builder =
                    s2n_security_policy_builder_from_version("20250721");
            EXPECT_NOT_NULL(builder);

            EXPECT_SUCCESS(s2n_security_policy_builder_free(&builder));
            EXPECT_NULL(builder);

            /* Freeing again is a no-op */
            EXPECT_SUCCESS(s2n_security_policy_builder_free(&builder));
            EXPECT_NULL(builder);
        };
    };

    /* Test: s2n_security_policy_build / s2n_security_policy_free */
    {
        /* Test: safety */
        {
            EXPECT_NULL_WITH_ERRNO(
                    s2n_security_policy_build(NULL),
                    S2N_ERR_INVALID_ARGUMENT);
            EXPECT_SUCCESS(s2n_security_policy_free(NULL));
            struct s2n_security_policy *policy = NULL;
            EXPECT_SUCCESS(s2n_security_policy_free(&policy));
        };

        /* Test: successfully build and free a policy */
        {
            DEFER_CLEANUP(struct s2n_security_policy_builder *builder =
                                  s2n_security_policy_builder_from_version("20250721"),
                    s2n_security_policy_builder_free);
            EXPECT_NOT_NULL(builder);

            struct s2n_security_policy *policy = s2n_security_policy_build(builder);
            EXPECT_NOT_NULL(policy);
            EXPECT_TRUE(policy->alloced);

            EXPECT_SUCCESS(s2n_security_policy_free(&policy));
            EXPECT_NULL(policy);

            /* Freeing again is a no-op */
            EXPECT_SUCCESS(s2n_security_policy_free(&policy));
            EXPECT_NULL(policy);
        };

        /* Test: builder copies policies */
        {
            DEFER_CLEANUP(struct s2n_security_policy_builder *builder =
                                  s2n_security_policy_builder_from_version("20250721"),
                    s2n_security_policy_builder_free);
            EXPECT_NOT_NULL(builder);

            DEFER_CLEANUP(struct s2n_security_policy *copy =
                                  s2n_security_policy_build(builder),
                    s2n_security_policy_free);
            EXPECT_NOT_NULL(copy);

            const struct s2n_security_policy *original = &security_policy_20250721;
            EXPECT_OK(s2n_security_policies_assert_match(copy, original));
        };
    };

    /* Test: validate with all current static policies */
    for (size_t policy_index = 0; security_policy_selection[policy_index].version != NULL; policy_index++) {
        const char *version = security_policy_selection[policy_index].version;
        const struct s2n_security_policy *policy =
                security_policy_selection[policy_index].security_policy;

        /* Test: can create builder from all static policies */
        {
            struct s2n_security_policy_builder *builder =
                    s2n_security_policy_builder_from_version(version);
            EXPECT_NOT_NULL(builder);
            EXPECT_SUCCESS(s2n_security_policy_builder_free(&builder));
        };

        /* Test: can build with all static policies */
        {
            DEFER_CLEANUP(struct s2n_security_policy_builder *builder =
                                  s2n_security_policy_builder_from_version(version),
                    s2n_security_policy_builder_free);
            EXPECT_NOT_NULL(builder);

            struct s2n_security_policy *copy = s2n_security_policy_build(builder);
            EXPECT_NOT_NULL(copy);
            EXPECT_OK(s2n_security_policies_assert_match(copy, policy));
            EXPECT_SUCCESS(s2n_security_policy_free(&copy));
        };

        /* Test: cannot free any static policy */
        {
            struct s2n_security_policy *non_const_policy =
                    (struct s2n_security_policy *) (void *) (uintptr_t) (const void *) policy;
            EXPECT_FAILURE_WITH_ERRNO(
                    s2n_security_policy_free(&non_const_policy),
                    S2N_ERR_INVALID_ARGUMENT);
        };
    }

    END_TEST();
}
