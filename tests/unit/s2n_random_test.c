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

#ifdef __FreeBSD__
    /* FreeBSD requires POSIX compatibility off for its syscalls (enables __BSD_VISIBLE)
     * Without the below line, <sys/wait.h> cannot be imported (it requires __BSD_VISIBLE) */
    #undef _POSIX_C_SOURCE
#else
    /* For clone() */
    #define _GNU_SOURCE
#endif

#include "utils/s2n_random.h"

#include <openssl/rand.h>
#include <pthread.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

#include "api/s2n.h"
#include "crypto/s2n_fips.h"
#include "crypto/s2n_libcrypto.h"
#include "s2n_test.h"

#define MAX_NUMBER_OF_TEST_THREADS 2

#define CLONE_TEST_NO                   0
#define CLONE_TEST_YES                  1
#define CLONE_TEST_DETERMINE_AT_RUNTIME 2

#define RANDOM_GENERATE_DATA_SIZE     100
#define MAX_RANDOM_GENERATE_DATA_SIZE 5120

#define NUMBER_OF_BOUNDS               10
#define NUMBER_OF_RANGE_FUNCTION_CALLS 200
#define MAX_REPEATED_OUTPUT            4

bool s2n_libcrypto_is_fips(void);
bool s2n_libcrypto_is_openssl(void);
S2N_RESULT s2n_rand_device_validate(struct s2n_rand_device *device);
S2N_RESULT s2n_rand_get_urandom_for_test(struct s2n_rand_device **device);

struct random_test_case {
    const char *test_case_label;
    int (*test_case_cb)(struct random_test_case *test_case);
    int test_case_must_pass_clone_test;
    int expected_return_status;
};

struct random_communication {
    S2N_RESULT (*s2n_get_random_data_cb_1)(struct s2n_blob *blob);
    S2N_RESULT (*s2n_get_random_data_cb_2)(struct s2n_blob *blob);
    uint8_t thread_data[RANDOM_GENERATE_DATA_SIZE];
    int *pipes;
};

static void s2n_verify_child_exit_status(pid_t proc_pid, int expected_status)
{
    int status = 0;
#if S2N_CLONE_SUPPORTED
    EXPECT_EQUAL(waitpid(proc_pid, &status, __WALL), proc_pid);
#else
    /* __WALL is not relevant when clone() is not supported
     * https://man7.org/linux/man-pages/man2/wait.2.html#NOTES
     */
    EXPECT_EQUAL(waitpid(proc_pid, &status, 0), proc_pid);
#endif
    /* Check that child exited with status = expected_status. If not, this
     * indicates that an error was encountered in the unit tests executed in
     * that child process.
     */
    EXPECT_NOT_EQUAL(WIFEXITED(status), 0);
    EXPECT_EQUAL(WEXITSTATUS(status), expected_status);
}

int qsort_comparator(const void *pval1, const void *pval2)
{
    const uint64_t val1 = *(const uint64_t *) pval1;
    const uint64_t val2 = *(const uint64_t *) pval2;

    if (val1 < val2) {
        return -1;
    } else if (val1 > val2) {
        return 1;
    } else {
        return 0;
    }
}

void *s2n_thread_test_cb(void *thread_comms)
{
    struct random_communication *thread_comms_ptr = (struct random_communication *) thread_comms;

    struct s2n_blob thread_blob = { 0 };
    EXPECT_SUCCESS(s2n_blob_init(&thread_blob, thread_comms_ptr->thread_data, RANDOM_GENERATE_DATA_SIZE));

    EXPECT_NOT_NULL(thread_comms_ptr->s2n_get_random_data_cb_1);
    EXPECT_OK(thread_comms_ptr->s2n_get_random_data_cb_1(&thread_blob));

    return NULL;
}

static int s2n_random_test_case_failure_cb(struct random_test_case *test_case)
{
    EXPECT_SUCCESS(s2n_init());

    /* This is a cheap way to ensure that failures in a fork bubble up to the
     * parent as a failure. This should be caught in the parent when querying
     * the return status code of the child. All s2n test macros will cause a
     * process to exit with error status = 1. We call exit() directly to avoid
     * messages being printed on stderr, in turn, appearing in logs.
     */
    exit(1);

    EXPECT_SUCCESS(s2n_cleanup());

    return EXIT_SUCCESS;
}

static int s2n_random_noop_destructor_test_cb(struct random_test_case *test_case)
{
    /* Ensure that the destructor / cleanup does not require s2n_init to have been called.
     * If applications load s2n-tls but do not actually use it, our cleanup should not fail.
     *
     * Other test cases may currently trigger this scenario if the feature they
     * intend to test is not available so they exit before calling s2n_init.
     */
    return EXIT_SUCCESS;
}

static int s2n_random_rand_bytes_after_cleanup_cb(struct random_test_case *test_case)
{
    EXPECT_SUCCESS(s2n_init());
    EXPECT_SUCCESS(s2n_cleanup_final());

    unsigned char rndbytes[16];
    EXPECT_EQUAL(RAND_bytes(rndbytes, sizeof(rndbytes)), 1);

    return S2N_SUCCESS;
}

struct random_test_case random_test_cases[] = {
    { "Test destructor without s2n_init", s2n_random_noop_destructor_test_cb, CLONE_TEST_DETERMINE_AT_RUNTIME, EXIT_SUCCESS },
    /* The s2n FAIL_MSG() macro uses exit(1) not exit(EXIT_FAILURE). So, we need
     * to use 1 below and in s2n_random_test_case_failure_cb().
     */
    { "Test failure.", s2n_random_test_case_failure_cb, CLONE_TEST_DETERMINE_AT_RUNTIME, 1 },
    { "Test libcrypto's RAND engine is reset correctly after manual s2n_cleanup()", s2n_random_rand_bytes_after_cleanup_cb, CLONE_TEST_DETERMINE_AT_RUNTIME, EXIT_SUCCESS },
};

int main(int argc, char **argv)
{
    BEGIN_TEST_NO_INIT();

    /* Feature probe: Negative test */
    {
        if (s2n_libcrypto_is_awslc()) {
#if defined(S2N_LIBCRYPTO_SUPPORTS_ENGINE)
            FAIL_MSG("Expected ENGINE feature probe to be disabled with AWS-LC");
#endif
        }

        if (s2n_libcrypto_is_openssl_fips()) {
#if !S2N_LIBCRYPTO_SUPPORTS_PRIVATE_RAND
            FAIL_MSG("Expected private rand support from openssl3 fips");
#endif
        }
    };

    /* Feature probe: Positive test
     *
     * TODO: Test missing due to unrelated feature probe failure on AL2.
     * https://github.com/aws/s2n-tls/issues/4900
     */

    /* Test: s2n_use_libcrypto_rand() returns the expected value based on
     * whether the linked libcrypto supports RAND_priv_bytes or RAND_public_bytes.
     * Validates: Requirements 1.1, 1.2, 2.1, 2.2, 2.3, 2.4
     */
    {
#if defined(S2N_LIBCRYPTO_SUPPORTS_PRIVATE_RAND) || defined(S2N_LIBCRYPTO_SUPPORTS_PUBLIC_RAND)
        bool expected = true;
#else
        bool expected = false;
#endif
        EXPECT_EQUAL(s2n_use_libcrypto_rand(), expected);
    };

    /* For each test case, creates a child process that runs the test case. */
    for (size_t i = 0; i < s2n_array_len(random_test_cases); i++) {
        pid_t proc_id = 0;

        proc_id = fork();
        EXPECT_TRUE(proc_id >= 0);

        if (proc_id == 0) {
            /* In child */
            EXPECT_EQUAL(random_test_cases[i].test_case_cb(&random_test_cases[i]), EXIT_SUCCESS);

            /* Exit code EXIT_SUCCESS means that tests in this process finished
             * successfully. Any errors would have exited the process with an
             * exit code != EXIT_SUCCESS. We verify this in the parent process.
             * Also prevents child from creating more children.
             */
            exit(EXIT_SUCCESS);
        } else {
            s2n_verify_child_exit_status(proc_id, random_test_cases[i].expected_return_status);
        }
    }

    /* We are very paranoid when it comes to randomness. So, run the basic test
     * set without using the fork infrastructure above.
     */
    EXPECT_EQUAL(random_test_cases[0].test_case_cb(&random_test_cases[0]), EXIT_SUCCESS);

    END_TEST_NO_INIT();
}
