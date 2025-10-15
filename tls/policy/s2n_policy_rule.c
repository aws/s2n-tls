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

#include "error/s2n_errno.h"
#include "tls/s2n_security_policies.h"
#include "utils/s2n_safety.h"

const struct s2n_policy_rule *policy_rules[S2N_POLICY_RULE_COUNT + 1] = {
    [S2N_POLICY_RULE_PQ] = &pq_policy_rule,
};

static const struct s2n_policy_rule *s2n_policy_rule_get(s2n_security_policy_rule name)
{
    PTR_ENSURE((uint64_t) name < s2n_array_len(policy_rules), S2N_ERR_INVALID_ARGUMENT);
    const struct s2n_policy_rule *rule = policy_rules[name];
    PTR_ENSURE(rule, S2N_ERR_INVALID_ARGUMENT);
    return rule;
}

S2N_RESULT s2n_policy_rule_list_enable(struct s2n_policy_rule_list *list,
        s2n_security_policy_rule name, uint64_t version)
{
    RESULT_ENSURE_REF(list);
    const struct s2n_policy_rule *rule = s2n_policy_rule_get(name);
    RESULT_GUARD_PTR(rule);
    RESULT_ENSURE(0 < version && version <= rule->max_valid_version, S2N_ERR_INVALID_ARGUMENT);
    list->rule_versions[name] = version;
    return S2N_RESULT_OK;
}

S2N_RESULT s2n_policy_rule_list_apply(struct s2n_policy_rule_list *list,
        struct s2n_security_policy *policy)
{
    RESULT_ENSURE_REF(list);
    RESULT_ENSURE_REF(policy);
    RESULT_ENSURE_EQ(policy->alloced, true);

    /* Perform the rule operations in the prescribed order.
     * See `s2n_policy_rule_op` for further explanation.
     */
    for (size_t op_i = 0; op_i < S2N_POLICY_RULE_OP_COUNT; op_i++) {
        for (size_t rule_i = 0; rule_i <= S2N_POLICY_RULE_COUNT; rule_i++) {
            const struct s2n_policy_rule *rule = policy_rules[rule_i];
            const uint64_t version = list->rule_versions[rule_i];
            if (rule && version && rule->ops[op_i]) {
                RESULT_ENSURE_INCLUSIVE_RANGE(1, version, rule->max_valid_version);
                RESULT_GUARD(rule->ops[op_i](policy, version));
            }
        }
    }

    return S2N_RESULT_OK;
}
