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

#include "crypto/s2n_pq.h"
#include "s2n_test.h"
#include "testlib/s2n_testlib.h"
#include "tests/s2n_test.h"
#include "tls/s2n_kem.h"
#include "tls/s2n_security_policies.h"
#include "tls/s2n_supported_group_preferences.h"
#include "tls/s2n_tls.h"

int main(int argc, char **argv)
{
    BEGIN_TEST();

    /* Enforce minimum requirements on all security policies that have strongly preferred groups */
    for (size_t policy_index = 0; security_policy_selection[policy_index].version != NULL; policy_index++) {
        const struct s2n_security_policy_selection selection = security_policy_selection[policy_index];
        const char *policy_name = selection.version;
        const struct s2n_security_policy *security_policy = selection.security_policy;
        POSIX_ENSURE_REF(security_policy);

        if (security_policy->strongly_preferred_groups == NULL || security_policy->strongly_preferred_groups->count == 0) {
            continue;
        }

        POSIX_ENSURE_REF(security_policy->strongly_preferred_groups);

        uint16_t ordered_supported_groups[S2N_KEM_GROUPS_COUNT + S2N_ECC_EVP_SUPPORTED_CURVES_COUNT] = { 0 };
        uint16_t ordered_supported_group_count = 0;

        POSIX_ENSURE_REF(security_policy->kem_preferences);

        /* Temporarily require that policies don't allow both PQ and strongly supported groups. */
        EXPECT_EQUAL(0, security_policy->kem_preferences->tls13_kem_group_count);

        POSIX_ENSURE_REF(security_policy->ecc_preferences);
        for (size_t i = 0; i < security_policy->ecc_preferences->count; i++) {
            const struct s2n_ecc_named_curve *ecc_curve = security_policy->ecc_preferences->ecc_curves[i];
            POSIX_ENSURE_REF(ecc_curve);

            ordered_supported_groups[ordered_supported_group_count++] = ecc_curve->iana_id;
        }

        /* Ensure ordering of strongly preferred IANA's matches the PQ and ECC preference ordering. */
        for (size_t i = 0; i < security_policy->strongly_preferred_groups->count; i++) {
            const uint16_t strongly_preferred_iana = security_policy->strongly_preferred_groups->iana_ids[i];
            const uint16_t standard_preferred_iana = ordered_supported_groups[i];

            /* Ensure that PQ supported groups aren't skipped as that could cause downgrades to ECC. */
            if (strongly_preferred_iana != standard_preferred_iana) {
                fprintf(stderr, "Error with Security Policy: %s\n", policy_name);
                FAIL_MSG("The strongly preferred groups should be a prefix of the standard SupportedGroup preference list.");
            }

            EXPECT_EQUAL(strongly_preferred_iana, standard_preferred_iana);
        }
    }

    END_TEST();
}
