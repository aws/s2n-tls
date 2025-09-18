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

DEFINE_POINTER_CLEANUP_FUNC(char *, unlink);

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

    /* Test: s2n_security_policy_write_length */
    {
        /* Test: safety - NULL policy */
        {
            uint32_t length;
            EXPECT_FAILURE_WITH_ERRNO(
                    s2n_security_policy_write_length(NULL, S2N_POLICY_FORMAT_DEBUG_V1, &length),
                    S2N_ERR_NULL);
        };

        /* Test: safety - NULL length pointer */
        {
            const struct s2n_security_policy *policy = NULL;
            EXPECT_SUCCESS(s2n_find_security_policy_from_version("default", &policy));
            EXPECT_NOT_NULL(policy);

            EXPECT_FAILURE_WITH_ERRNO(
                    s2n_security_policy_write_length(policy, S2N_POLICY_FORMAT_DEBUG_V1, NULL),
                    S2N_ERR_NULL);
        };

        /* Test: safety - invalid format */
        {
            const struct s2n_security_policy *policy = NULL;
            EXPECT_SUCCESS(s2n_find_security_policy_from_version("default", &policy));
            EXPECT_NOT_NULL(policy);

            uint32_t length;
            EXPECT_FAILURE_WITH_ERRNO(
                    s2n_security_policy_write_length(policy, 999, &length),
                    S2N_ERR_INVALID_ARGUMENT);
        };

        /* Test: successful length calculation and consistency with write_bytes */
        {
            const struct s2n_security_policy *policy = NULL;
            EXPECT_SUCCESS(s2n_find_security_policy_from_version("default", &policy));
            EXPECT_NOT_NULL(policy);

            uint32_t required_length = 0;
            EXPECT_SUCCESS(s2n_security_policy_write_length(policy, S2N_POLICY_FORMAT_DEBUG_V1, &required_length));
            EXPECT_TRUE(required_length > 0);

            DEFER_CLEANUP(struct s2n_blob exact_buffer = { 0 }, s2n_free);
            EXPECT_SUCCESS(s2n_alloc(&exact_buffer, required_length));
            EXPECT_SUCCESS(s2n_security_policy_write_bytes(policy, S2N_POLICY_FORMAT_DEBUG_V1, exact_buffer.data, required_length));

            EXPECT_OK(s2n_verify_format_v1_output((const char *) exact_buffer.data));

            /* a buffer one byte smaller should fail */
            if (required_length > 1) {
                DEFER_CLEANUP(struct s2n_blob small_buffer = { 0 }, s2n_free);
                EXPECT_SUCCESS(s2n_alloc(&small_buffer, required_length - 1));
                EXPECT_FAILURE_WITH_ERRNO(
                        s2n_security_policy_write_bytes(policy, S2N_POLICY_FORMAT_DEBUG_V1, small_buffer.data, required_length - 1),
                        S2N_ERR_INSUFFICIENT_MEM_SIZE);
            }
        };
    };

    /* Test: s2n_security_policy_write_bytes */
    {
        /* Test: safety - NULL policy */
        {
            uint8_t buffer[1024];
            EXPECT_FAILURE_WITH_ERRNO(
                    s2n_security_policy_write_bytes(NULL, S2N_POLICY_FORMAT_DEBUG_V1, buffer, sizeof(buffer)),
                    S2N_ERR_NULL);
        };

        /* Test: safety - NULL buffer */
        {
            const struct s2n_security_policy *policy = NULL;
            EXPECT_SUCCESS(s2n_find_security_policy_from_version("default", &policy));
            EXPECT_NOT_NULL(policy);

            EXPECT_FAILURE_WITH_ERRNO(
                    s2n_security_policy_write_bytes(policy, S2N_POLICY_FORMAT_DEBUG_V1, NULL, 1024),
                    S2N_ERR_NULL);
        };

        /* Test: safety - invalid format */
        {
            const struct s2n_security_policy *policy = NULL;
            EXPECT_SUCCESS(s2n_find_security_policy_from_version("default", &policy));
            EXPECT_NOT_NULL(policy);

            uint8_t buffer[1024];
            EXPECT_FAILURE_WITH_ERRNO(
                    s2n_security_policy_write_bytes(policy, 999, buffer, sizeof(buffer)),
                    S2N_ERR_INVALID_ARGUMENT);
        };

        /* Test: buffer too small */
        {
            const struct s2n_security_policy *policy = NULL;
            EXPECT_SUCCESS(s2n_find_security_policy_from_version("default", &policy));
            EXPECT_NOT_NULL(policy);

            uint8_t small_buffer[10];
            EXPECT_FAILURE_WITH_ERRNO(
                    s2n_security_policy_write_bytes(policy, S2N_POLICY_FORMAT_DEBUG_V1, small_buffer, sizeof(small_buffer)),
                    S2N_ERR_INSUFFICIENT_MEM_SIZE);
        };

        /* Test: successful buffer write and content verification */
        {
            const struct s2n_security_policy *policy = NULL;
            EXPECT_SUCCESS(s2n_find_security_policy_from_version("default", &policy));
            EXPECT_NOT_NULL(policy);

            uint32_t required_length = 0;
            EXPECT_SUCCESS(s2n_security_policy_write_length(policy, S2N_POLICY_FORMAT_DEBUG_V1, &required_length));

            DEFER_CLEANUP(struct s2n_blob buffer = { 0 }, s2n_free);
            EXPECT_SUCCESS(s2n_alloc(&buffer, required_length));
            EXPECT_SUCCESS(s2n_security_policy_write_bytes(policy, S2N_POLICY_FORMAT_DEBUG_V1, buffer.data, required_length));

            EXPECT_OK(s2n_verify_format_v1_output((const char *) buffer.data));
        };
    };

    /* Test: s2n_security_policy_write_fd */
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

        /* Test: s2n_security_policy_write_fd - FORMAT_V1 structure verification */
        {
            const struct s2n_security_policy *policy = NULL;
            EXPECT_SUCCESS(s2n_find_security_policy_from_version("default", &policy));
            EXPECT_NOT_NULL(policy);

            uint32_t expected_length = 0;
            EXPECT_SUCCESS(s2n_security_policy_write_length(policy, S2N_POLICY_FORMAT_DEBUG_V1, &expected_length));

            /* Create a temp file */
            char temp_filename[] = "/tmp/s2n_policy_test_XXXXXX";
            int temp_fd = mkstemp(temp_filename);
            EXPECT_TRUE(temp_fd >= 0);
            DEFER_CLEANUP(char *temp_filename_ptr = temp_filename, unlink_pointer);

            EXPECT_SUCCESS(s2n_security_policy_write_fd(policy, S2N_POLICY_FORMAT_DEBUG_V1, temp_fd));
            EXPECT_SUCCESS(close(temp_fd));

            /* Read file content back */
            FILE *file = fopen(temp_filename, "r");
            EXPECT_NOT_NULL(file);
            DEFER_CLEANUP(struct s2n_blob file_buffer = { 0 }, s2n_free);
            EXPECT_SUCCESS(s2n_alloc(&file_buffer, expected_length + 1));
            size_t bytes_read = fread(file_buffer.data, 1, expected_length, file);
            EXPECT_EQUAL(bytes_read, expected_length);
            EXPECT_EQUAL(fclose(file), 0);

            EXPECT_OK(s2n_verify_format_v1_output((const char *) file_buffer.data));
        };
    };

    END_TEST();
}
