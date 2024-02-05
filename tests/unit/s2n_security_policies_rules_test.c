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

int main(int argc, char **argv)
{
    BEGIN_TEST();

    DEFER_CLEANUP(struct s2n_security_rule_result result = { 0 },
            s2n_security_rule_result_free);
    EXPECT_OK(s2n_security_rule_result_init_output(&result));

    for (size_t i = 0; security_policy_selection[i].version != NULL; i++) {
        const struct s2n_security_policy *security_policy = security_policy_selection[i].security_policy;
        EXPECT_NOT_NULL(security_policy);
        EXPECT_OK(s2n_security_policy_validate_security_rules(security_policy, &result));
    }

    if (result.found_error) {
        int output_size = s2n_stuffer_data_available(&result.output);
        char *output_str = s2n_stuffer_raw_read(&result.output, output_size);
        EXPECT_NOT_NULL(output_str);
        fprintf(stdout, "\n%.*s", output_size, output_str);
        FAIL_MSG("Security policies violate configured policy rules. See stdout for details.");
    }

    END_TEST();
}
