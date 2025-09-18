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

#include <fcntl.h>
#include <string.h>
#include <unistd.h>

#include "s2n_test.h"
#include "testlib/s2n_testlib.h"
#include "tls/policy/s2n_policy_feature.h"

/* A custom cleanup function for unlink 
 * We need this because unlink expects a const char* but DEFER_CLEANUP passes
 * the address of the variable, so we need a function that takes a char** and
 * calls unlink with the dereferenced pointer.
 */
static void s2n_unlink_cleanup(char **filename)
{
    if (filename && *filename) {
        unlink(*filename);
    }
}

static S2N_RESULT s2n_verify_format_v1_output(const char *output)
{
    RESULT_ENSURE_REF(output);

    /* Required sections are present */
    RESULT_ENSURE(strstr(output, "min version: ") != NULL, S2N_ERR_TEST_ASSERTION);
    RESULT_ENSURE(strstr(output, "rules:\n") != NULL, S2N_ERR_TEST_ASSERTION);
    RESULT_ENSURE(strstr(output, "cipher suites:\n") != NULL, S2N_ERR_TEST_ASSERTION);
    RESULT_ENSURE(strstr(output, "signature schemes:\n") != NULL, S2N_ERR_TEST_ASSERTION);
    RESULT_ENSURE(strstr(output, "curves:\n") != NULL, S2N_ERR_TEST_ASSERTION);

    return S2N_RESULT_OK;
}

int main(int argc, char **argv)
{
    BEGIN_TEST();

    /* Test: s2n_security_policy_write */
    {
        /* Test: safety - NULL policy */
        {
            EXPECT_FAILURE_WITH_ERRNO(
                    s2n_security_policy_write_fd(NULL, S2N_POLICY_FORMAT_DEBUG_V1, STDOUT_FILENO),
                    S2N_ERR_NULL);
        };

        /* Test: safety - invalid format */
        {
            const struct s2n_security_policy *policy = NULL;
            EXPECT_SUCCESS(s2n_find_security_policy_from_version("default", &policy));
            EXPECT_NOT_NULL(policy);

            EXPECT_FAILURE_WITH_ERRNO(
                    s2n_security_policy_write_fd(policy, 999, STDOUT_FILENO),
                    S2N_ERR_INVALID_ARGUMENT);
        };

        /* Test: safety - invalid file descriptor */
        {
            const struct s2n_security_policy *policy = NULL;
            EXPECT_SUCCESS(s2n_find_security_policy_from_version("default", &policy));
            EXPECT_NOT_NULL(policy);

            EXPECT_FAILURE_WITH_ERRNO(
                    s2n_security_policy_write_fd(policy, S2N_POLICY_FORMAT_DEBUG_V1, -1),
                    S2N_ERR_INVALID_ARGUMENT);
        };

        /* Test: s2n_security_policy_write - FORMAT_V1 structure verification */
        {
            /* Pick a few named policies for sanity checking. Snapshot tests verify the exact content. */
            const char *test_policies[] = {
                "default",
                "default_fips",
                "default_tls13",
                "default_pq",
                NULL
            };

            for (size_t i = 0; test_policies[i] != NULL; i++) {
                const char *policy_version = test_policies[i];
                const struct s2n_security_policy *policy = NULL;
                EXPECT_SUCCESS(s2n_find_security_policy_from_version(policy_version, &policy));
                EXPECT_NOT_NULL(policy);

                /* Create a temp file */
                char temp_filename[] = "/tmp/s2n_policy_test_XXXXXX";
                int temp_fd = mkstemp(temp_filename);
                EXPECT_TRUE(temp_fd >= 0);
                DEFER_CLEANUP(char *temp_filename_ptr = temp_filename, s2n_unlink_cleanup);

                /* Write policy to file */
                EXPECT_SUCCESS(s2n_security_policy_write_fd(policy, S2N_POLICY_FORMAT_DEBUG_V1, temp_fd));
                EXPECT_SUCCESS(close(temp_fd));

                /* Read file content back */
                FILE *file = fopen(temp_filename, "r");
                EXPECT_NOT_NULL(file);
                char file_buffer[8192] = { 0 };
                size_t bytes_read = fread(file_buffer, 1, sizeof(file_buffer) - 1, file);
                EXPECT_TRUE(bytes_read > 0);
                EXPECT_EQUAL(fclose(file), 0);

                EXPECT_OK(s2n_verify_format_v1_output(file_buffer));
            }
        };
    };

    /* Test: s2n_security_policy_write_buffer */
    {
        /* Test: safety - NULL policy */
        {
            uint8_t buffer[1024];
            EXPECT_FAILURE_WITH_ERRNO(
                    s2n_security_policy_write_buffer(NULL, S2N_POLICY_FORMAT_DEBUG_V1, buffer, sizeof(buffer)),
                    S2N_ERR_NULL);
        };

        /* Test: safety - NULL buffer */
        {
            const struct s2n_security_policy *policy = NULL;
            EXPECT_SUCCESS(s2n_find_security_policy_from_version("default", &policy));
            EXPECT_NOT_NULL(policy);

            EXPECT_FAILURE_WITH_ERRNO(
                    s2n_security_policy_write_buffer(policy, S2N_POLICY_FORMAT_DEBUG_V1, NULL, 1024),
                    S2N_ERR_NULL);
        };

        /* Test: safety - invalid format */
        {
            const struct s2n_security_policy *policy = NULL;
            EXPECT_SUCCESS(s2n_find_security_policy_from_version("default", &policy));
            EXPECT_NOT_NULL(policy);

            uint8_t buffer[1024];
            EXPECT_FAILURE_WITH_ERRNO(
                    s2n_security_policy_write_buffer(policy, 999, buffer, sizeof(buffer)),
                    S2N_ERR_INVALID_ARGUMENT);
        };

        /* Test: buffer too small */
        {
            const struct s2n_security_policy *policy = NULL;
            EXPECT_SUCCESS(s2n_find_security_policy_from_version("default", &policy));
            EXPECT_NOT_NULL(policy);

            uint8_t small_buffer[10];
            EXPECT_FAILURE_WITH_ERRNO(
                    s2n_security_policy_write_buffer(policy, S2N_POLICY_FORMAT_DEBUG_V1, small_buffer, sizeof(small_buffer)),
                    S2N_ERR_INSUFFICIENT_MEM_SIZE);
        };

        /* Test: successful buffer write and content verification */
        {
            const struct s2n_security_policy *policy = NULL;
            EXPECT_SUCCESS(s2n_find_security_policy_from_version("default", &policy));
            EXPECT_NOT_NULL(policy);

            uint8_t buffer[8192];
            EXPECT_SUCCESS(s2n_security_policy_write_buffer(policy, S2N_POLICY_FORMAT_DEBUG_V1, buffer, sizeof(buffer)));

            EXPECT_OK(s2n_verify_format_v1_output((const char *) buffer));
        };
    };

    END_TEST();
}
