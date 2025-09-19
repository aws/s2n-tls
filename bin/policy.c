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

#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>

#include "api/s2n.h"
#include "tls/policy/s2n_policy_feature.h"
#include "tls/s2n_security_policies.h"

static int usage()
{
    printf("policy <version>\n"
           "example: policy default_tls13\n\n");
    return 0;
}

int main(int argc, char *const *argv)
{
    if (argc != 2) {
        usage();
        exit(1);
    }

    if (s2n_init() != S2N_SUCCESS) {
        fprintf(stderr, "Error: Failed to initialize s2n\n");
        exit(1);
    }

    const char *policy_name = argv[1];
    const struct s2n_security_policy *policy = NULL;
    if (s2n_find_security_policy_from_version(policy_name, &policy) != S2N_SUCCESS) {
        fprintf(stderr, "Error: Failed to find security policy\n");
        s2n_cleanup();
        exit(1);
    }

    if (s2n_security_policy_write_fd(policy, S2N_POLICY_FORMAT_DEBUG_V1, STDOUT_FILENO) != S2N_SUCCESS) {
        s2n_cleanup();
        exit(1);
    }
    s2n_cleanup();

    return 0;
}
