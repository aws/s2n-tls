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

#include "tls/policy/s2n_policy_builder.h"

#include "s2n_test.h"
#include "testlib/s2n_testlib.h"

int main(int argc, char **argv)
{
    BEGIN_TEST();

    /* Test: s2n_security_policy_get */
    {
        /* Policies exist only for expected policy + version combinations */
        for (size_t base_i = 0; base_i < UINT8_MAX; base_i++) {
            bool first_null_found = false;
            for (size_t version_i = 0; version_i < UINT8_MAX; version_i++) {
                const struct s2n_security_policy *policy = s2n_security_policy_get(base_i, version_i);
                if (base_i >= S2N_BASE_POLICIES_COUNT) {
                    EXPECT_NULL_WITH_ERRNO(policy, S2N_ERR_INVALID_SECURITY_POLICY);
                } else if (version_i == 0) {
                    EXPECT_NULL_WITH_ERRNO(policy, S2N_ERR_INVALID_SECURITY_POLICY);
                } else if (version_i >= S2N_MAX_POLICY_VERSIONS) {
                    EXPECT_NULL_WITH_ERRNO(policy, S2N_ERR_INVALID_SECURITY_POLICY);
                } else if (first_null_found) {
                    EXPECT_NOT_EQUAL(version_i, 0);
                    EXPECT_NULL_WITH_ERRNO(policy, S2N_ERR_INVALID_SECURITY_POLICY);
                } else if (!policy) {
                    first_null_found = true;
                    EXPECT_NULL_WITH_ERRNO(policy, S2N_ERR_INVALID_SECURITY_POLICY);
                }
            }
        }
    };

    END_TEST();
}
