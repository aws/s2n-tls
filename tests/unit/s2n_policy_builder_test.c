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
        for (size_t default_i = 0; default_i < UINT8_MAX; default_i++) {
            bool first_null_found = false;
            for (size_t version_i = 0; version_i < UINT8_MAX; version_i++) {
                const struct s2n_security_policy *policy = s2n_security_policy_get(default_i, version_i);

                /* Invalid policy or version values should be NULL */
                if (version_i == 0 || default_i == 0) {
                    /* Versioning starts at 1 instead of 0.
                     * We may want to later assign 0 a special meaning, like "none".
                     */
                    EXPECT_NULL_WITH_ERRNO(policy, S2N_ERR_INVALID_SECURITY_POLICY);
                    continue;
                } else if (default_i >= S2N_MAX_DEFAULT_POLICIES) {
                    EXPECT_NULL_WITH_ERRNO(policy, S2N_ERR_INVALID_SECURITY_POLICY);
                    continue;
                } else if (version_i >= S2N_MAX_POLICY_VERSIONS) {
                    EXPECT_NULL_WITH_ERRNO(policy, S2N_ERR_INVALID_SECURITY_POLICY);
                    continue;
                }

                if (policy) {
                    /* The policy exists because the version is valid.
                     * Versions should be contiguous. No previous gaps.
                     */
                    EXPECT_FALSE(first_null_found);
                } else if (first_null_found) {
                    /* If we've already found the first invalid version, all later
                     * versions should be invalid too.
                     */
                    EXPECT_NULL_WITH_ERRNO(policy, S2N_ERR_INVALID_SECURITY_POLICY);
                } else {
                    /* We have found the first invalid version */
                    first_null_found = true;
                    EXPECT_NULL_WITH_ERRNO(policy, S2N_ERR_INVALID_SECURITY_POLICY);
                }
            }
        }
    };

    END_TEST();
}
