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
#include "tls/s2n_kem.h"
#include "tls/s2n_security_policies.c"

const struct s2n_kem_group *pq_kem_groups_2025_08_20[] = {
    &s2n_x25519_mlkem_768,
    &s2n_secp256r1_mlkem_768,
    &s2n_secp384r1_mlkem_1024,
};
const struct s2n_kem_preferences kem_preferences_2025_08_20 = {
    .tls13_kem_group_count = s2n_array_len(pq_kem_groups_2025_08_20),
    .tls13_kem_groups = pq_kem_groups_2025_08_20,
    .tls13_pq_hybrid_draft_revision = 5
};

S2N_RESULT s2n_kem_preferences_copy(const struct s2n_kem_preferences *original,
        const struct s2n_kem_preferences **copy);
S2N_RESULT s2n_kem_preferences_free(const struct s2n_kem_preferences **prefs);

static S2N_RESULT s2n_pq_policy_rule_add(struct s2n_security_policy *policy, uint64_t version)
{
    /* TODO: full implementation.
     * For now, only perform a very simplistic version of the PQ rule,
     * assuming no existing PQ kem preferences.
     * We also intentionally ignore MLDSA for now.
     * This is really just for initial testing.
     */
    RESULT_ENSURE_EQ(version, S2N_RULE_PQ_2025_08_20);
    RESULT_ENSURE(policy->kem_preferences->tls13_kem_groups == 0,
            S2N_ERR_SECURITY_POLICY_DEFINITION);
    RESULT_GUARD(s2n_kem_preferences_free(&policy->kem_preferences));
    RESULT_GUARD(s2n_kem_preferences_copy(&kem_preferences_2025_08_20, &policy->kem_preferences));
    return S2N_RESULT_OK;
}

struct s2n_policy_rule pq_policy_rule = {
    .max_valid_version = S2N_RULE_PQ_LATEST,
    .ops = {
            [S2N_POLICY_RULE_ADD] = s2n_pq_policy_rule_add,
    }
};
