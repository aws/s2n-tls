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

#include "tls/policy/s2n_policy_rule.h"

#include "s2n_test.h"
#include "testlib/s2n_testlib.h"
#include "tls/s2n_security_policies.h"

int main(int argc, char **argv)
{
    BEGIN_TEST();

    /* Test: s2n_policy_rule_list_enable */
    {
        /* Safety */
        {
            struct s2n_policy_rule_list list = { 0 };
            EXPECT_ERROR_WITH_ERRNO(
                    s2n_policy_rule_list_enable(NULL, S2N_POLICY_RULE_PQ, S2N_RULE_PQ_2025_08_20),
                    S2N_ERR_NULL);
            EXPECT_ERROR_WITH_ERRNO(
                    s2n_policy_rule_list_enable(&list, 0, S2N_RULE_PQ_2025_08_20),
                    S2N_ERR_INVALID_ARGUMENT);
            EXPECT_ERROR_WITH_ERRNO(
                    s2n_policy_rule_list_enable(&list, S2N_POLICY_RULE_COUNT + 1, S2N_RULE_PQ_2025_08_20),
                    S2N_ERR_INVALID_ARGUMENT);
            EXPECT_ERROR_WITH_ERRNO(
                    s2n_policy_rule_list_enable(&list, S2N_POLICY_RULE_PQ, 0),
                    S2N_ERR_INVALID_ARGUMENT);
            EXPECT_ERROR_WITH_ERRNO(
                    s2n_policy_rule_list_enable(&list, S2N_POLICY_RULE_PQ, S2N_RULE_PQ_LATEST + 1),
                    S2N_ERR_INVALID_ARGUMENT);
            for (size_t i = 0; i < s2n_array_len(list.rule_versions); i++) {
                EXPECT_EQUAL(list.rule_versions[i], 0);
            }
        };

        /* Test: set a valid rule */
        {
            struct s2n_policy_rule_list list = { 0 };
            EXPECT_OK(s2n_policy_rule_list_enable(&list, S2N_POLICY_RULE_PQ, S2N_RULE_PQ_2025_08_20));
            for (size_t i = 0; i < s2n_array_len(list.rule_versions); i++) {
                if (i == S2N_POLICY_RULE_PQ) {
                    EXPECT_EQUAL(list.rule_versions[i], S2N_RULE_PQ_2025_08_20);
                } else {
                    EXPECT_EQUAL(list.rule_versions[i], 0);
                }
            }
        }
    };

    /* Test: s2n_policy_rule_list_apply */
    {
        /* Safety */
        {
            struct s2n_policy_rule_list list = { 0 };
            struct s2n_security_policy policy = security_policy_20240501;
            EXPECT_ERROR_WITH_ERRNO(
                    s2n_policy_rule_list_apply(NULL, &policy),
                    S2N_ERR_NULL);
            EXPECT_ERROR_WITH_ERRNO(
                    s2n_policy_rule_list_apply(&list, NULL),
                    S2N_ERR_NULL);
        };

        /* Test: successfully apply a rule */
        {
            /* Create an alloced, non-PQ policy to operate on */
            DEFER_CLEANUP(struct s2n_security_policy_builder *builder =
                                  s2n_security_policy_builder_from_version("20240501"),
                    s2n_security_policy_builder_free);
            EXPECT_NOT_NULL(builder);
            DEFER_CLEANUP(struct s2n_security_policy *policy = s2n_security_policy_build(builder),
                    s2n_security_policy_free);
            EXPECT_NOT_NULL(policy);
            EXPECT_NOT_NULL(policy->kem_preferences);
            EXPECT_EQUAL(policy->kem_preferences->tls13_kem_group_count, 0);
            EXPECT_NULL(policy->kem_preferences->tls13_kem_groups);

            struct s2n_policy_rule_list list = { 0 };
            EXPECT_OK(s2n_policy_rule_list_enable(&list, S2N_POLICY_RULE_PQ, S2N_RULE_PQ_2025_08_20));
            EXPECT_OK(s2n_policy_rule_list_apply(&list, policy));

            /* Modified policy includes PQ */
            EXPECT_NOT_NULL(policy);
            EXPECT_NOT_NULL(policy->kem_preferences);
            EXPECT_EQUAL(policy->kem_preferences->tls13_kem_group_count, 3);
            EXPECT_NOT_NULL(policy->kem_preferences->tls13_kem_groups);
        };

        /* Test: fail to apply a rule */
        {
            /* Create an alloced, already PQ policy to operate on.
             * For now the PQ rule only operates on non-PQ policies, so attempting
             * to modify a PQ policy will cause an error.
             */
            DEFER_CLEANUP(struct s2n_security_policy_builder *builder =
                                  s2n_security_policy_builder_from_version("20250721"),
                    s2n_security_policy_builder_free);
            EXPECT_NOT_NULL(builder);
            DEFER_CLEANUP(struct s2n_security_policy *policy = s2n_security_policy_build(builder),
                    s2n_security_policy_free);
            EXPECT_NOT_NULL(policy);
            EXPECT_NOT_NULL(policy->kem_preferences);
            EXPECT_EQUAL(policy->kem_preferences->tls13_kem_group_count, 3);

            struct s2n_policy_rule_list list = { 0 };
            EXPECT_OK(s2n_policy_rule_list_enable(&list, S2N_POLICY_RULE_PQ, S2N_RULE_PQ_2025_08_20));

            EXPECT_ERROR_WITH_ERRNO(s2n_policy_rule_list_apply(&list, policy),
                    S2N_ERR_SECURITY_POLICY_DEFINITION);
        };
    };

    END_TEST();
}
