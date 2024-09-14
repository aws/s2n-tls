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

#include <signal.h>
#include <stdio.h>
#include <sys/stat.h>

#include "s2n_test.h"
#include "testlib/s2n_testlib.h"

bool s2n_fstat_success = false;
bool s2n_open_success = false;

void s2n_detect_open_violation(int sig)
{
    EXPECT_EQUAL(sig, SIGSYS);

    EXPECT_TRUE(s2n_fstat_success);
    EXPECT_FALSE(s2n_open_success);

    END_TEST_PRINT();
    exit(0);
}

int main(int argc, char **argv)
{
    BEGIN_TEST();

    if (!s2n_is_seccomp_supported()) {
        END_TEST();
    }

    const struct sigaction action = {
        .sa_handler = s2n_detect_open_violation,
    };
    EXPECT_EQUAL(sigaction(SIGSYS, &action, NULL), 0);

    EXPECT_OK(s2n_seccomp_init());

    /* The seccomp filter allows fstat */
    struct stat st = { 0 };
    EXPECT_SUCCESS(fstat(0, &st));
    s2n_fstat_success = true;

    /* The seccomp filter does NOT allow open */
    FILE *file = fopen(S2N_DEFAULT_TEST_CERT_CHAIN, "r");
    s2n_open_success = true;
    EXPECT_NOT_NULL(file);

    FAIL_MSG("test unexpectedly succeeded");
}
