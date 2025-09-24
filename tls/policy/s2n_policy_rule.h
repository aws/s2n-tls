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

#pragma once

#include "tls/policy/s2n_policy_feature.h"
#include "utils/s2n_result.h"

#define S2N_POLICY_RULE_COUNT 1

/* Rules require separate, distinct operations performed in a predictable order
 * to interact with other rules properly.
 * 
 * For example, if a rule that adds TLS1.3 support adds a ChaChaPoly cipher suite
 * and a rule that enforces FIPS restrictions removes ChaChaPoly cipher suites,
 * then the 'add' must always occur before the 'remove' to produce a sane result.
 */
enum s2n_policy_rule_op {
    S2N_POLICY_RULE_ADD,
    S2N_POLICY_RULE_REMOVE,

    S2N_POLICY_RULE_CHECK,
    S2N_POLICY_RULE_OP_COUNT,
};

struct s2n_policy_rule {
    uint64_t max_valid_version;
    s2n_result (*ops[S2N_POLICY_RULE_OP_COUNT])(struct s2n_security_policy *, uint64_t);
};

struct s2n_policy_rule_list {
    uint64_t rule_versions[S2N_POLICY_RULE_COUNT + 1];
};

extern struct s2n_policy_rule pq_policy_rule;

S2N_RESULT s2n_policy_rule_list_enable(struct s2n_policy_rule_list *list,
        s2n_security_policy_rule name, uint64_t version);
S2N_RESULT s2n_policy_rule_list_apply(struct s2n_policy_rule_list *list,
        struct s2n_security_policy *policy);
