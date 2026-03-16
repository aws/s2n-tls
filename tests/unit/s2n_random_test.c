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

/* Very basic test generating random data a few times and checking that the
 * output is different
 */
static S2N_RESULT s2n_basic_generate_tests(void)
{
    uint8_t data1[RANDOM_GENERATE_DATA_SIZE];
    uint8_t data2[RANDOM_GENERATE_DATA_SIZE];
    struct s2n_blob blob1 = { 0 };
    EXPECT_SUCCESS(s2n_blob_init(&blob1, data1, 0));
    struct s2n_blob blob2 = { 0 };
    EXPECT_SUCCESS(s2n_blob_init(&blob2, data2, 0));

    /* Generate two random data blobs and confirm that they are unique */
    blob1.size = RANDOM_GENERATE_DATA_SIZE;
    blob2.size = RANDOM_GENERATE_DATA_SIZE;
    EXPECT_OK(s2n_get_public_random_data(&blob1));
    EXPECT_OK(s2n_get_public_random_data(&blob2));
    EXPECT_BYTEARRAY_NOT_EQUAL(data1, data2, RANDOM_GENERATE_DATA_SIZE);
    EXPECT_OK(s2n_get_private_random_data(&blob1));
    EXPECT_BYTEARRAY_NOT_EQUAL(data1, data2, RANDOM_GENERATE_DATA_SIZE);
    EXPECT_OK(s2n_get_private_random_data(&blob2));
    EXPECT_BYTEARRAY_NOT_EQUAL(data1, data2, RANDOM_GENERATE_DATA_SIZE);

    return S2N_RESULT_OK;
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

static S2N_RESULT s2n_tests_get_range(void)
{
    uint64_t range_results[NUMBER_OF_RANGE_FUNCTION_CALLS] = { 0 };
    uint64_t current_output = 0;
    /* The type of the `bound` parameter in s2n_public_random() is signed */
    int64_t chosen_upper_bound = 0;
    struct s2n_blob upper_bound_blob = { 0 };
    EXPECT_SUCCESS(s2n_blob_init(&upper_bound_blob, (void *) &chosen_upper_bound, sizeof(chosen_upper_bound)));

    /* 0 is not a legal upper bound */
    chosen_upper_bound = 0;
    EXPECT_ERROR_WITH_ERRNO(s2n_public_random(chosen_upper_bound, &current_output), S2N_ERR_SAFETY);

    /* For an upper bound of 1, 0 should be the only possible output */
    chosen_upper_bound = 1;
    EXPECT_OK(s2n_public_random(chosen_upper_bound, &current_output));
    EXPECT_EQUAL(current_output, 0);

    /* For a upper bound of 2, 0 and 1 should be the only possible outputs */
    chosen_upper_bound = 1;
    EXPECT_OK(s2n_public_random(chosen_upper_bound, &current_output));
    EXPECT_TRUE((current_output == 0) || (current_output == 1));

    /* Test NUMBER_OF_BOUNDS upper bounds. For each resulting range, draw
     * NUMBER_OF_RANGE_FUNCTION_CALLS numbers from s2n_public_random() and
     * verify the output. Set 2^30 * NUMBER_OF_RANGE_FUNCTION_CALLS as the
     * minimal value for the upper bound. The minimal upper bound value is
     * chosen to make the likelihood of a false positive small - see below for
     * probability calculations.
     */
    int64_t minimal_upper_bound = (int64_t) 0x40000000 * (int64_t) NUMBER_OF_RANGE_FUNCTION_CALLS;
    for (size_t bound_ctr = 0; bound_ctr < NUMBER_OF_BOUNDS; bound_ctr++) {
        /* chosen_upper_bound is supposedly chosen uniformly at random and
         * minimal_upper_bound is only 2^30 * NUMBER_OF_RANGE_FUNCTION_CALLS, so
         * this should not iterate for too long
         */
        do {
            EXPECT_OK(s2n_get_private_random_data(&upper_bound_blob));
        } while (chosen_upper_bound < minimal_upper_bound);

        /* Pick NUMBER_OF_RANGE_FUNCTION_CALLS numbers in the given interval.
         * While doing that, also verify that the upper bound is respected.
         */
        for (size_t func_call_ctr = 0; func_call_ctr < NUMBER_OF_RANGE_FUNCTION_CALLS; func_call_ctr++) {
            EXPECT_OK(s2n_public_random(chosen_upper_bound, &range_results[func_call_ctr]));
            EXPECT_TRUE(range_results[func_call_ctr] < chosen_upper_bound);
        }

        /* The probability of "at least MAX_REPEATED_OUTPUT repeated values"
         * follows a binomial distribution. Hence, we can get an upper bound via
         * Markov's inequality:
         * P("at least MAX_REPEATED_OUTPUT repeated values")
         *      <= E("at least MAX_REPEATED_OUTPUT repeated values") / MAX_REPEATED_OUTPUT.
         *       = (NUMBER_OF_RANGE_FUNCTION_CALLS * 1/(2^30 * NUMBER_OF_RANGE_FUNCTION_CALLS)) / MAX_REPEATED_OUTPUT
         *       = 1/(2^30 * MAX_REPEATED_OUTPUT)
         *
         * With current parameters
         *   NUMBER_OF_BOUNDS = 10
         *   MAX_REPEATED_OUTPUT = 4
         * this ends up with about a ~1/2^30 probability of failing this test
         * with a false positive.
         *
         * qsort() complexity is not guaranteed, but
         * NUMBER_OF_RANGE_FUNCTION_CALLS is very small, so no biggie.
         * Sorting the array means that we can check for repeated numbers by
         * just counting from left to right resetting the count when meeting a
         * different value.
         */
        qsort(range_results, NUMBER_OF_RANGE_FUNCTION_CALLS, sizeof(uint64_t),
                qsort_comparator);
        uint64_t current_value = range_results[0];
        uint64_t next_value = 0;
        size_t repeat_count = 1;
        for (size_t ctr = 1; ctr < NUMBER_OF_RANGE_FUNCTION_CALLS - 1; ctr++) {
            next_value = range_results[ctr];

            if (current_value == next_value) {
                repeat_count = repeat_count + 1;
            } else {
                RESULT_ENSURE_LT(current_value, next_value);
                current_value = next_value;
                repeat_count = 1;
            }

            EXPECT_TRUE(repeat_count < MAX_REPEATED_OUTPUT);
        }

        /* Reset for next iteration */
        RESULT_CHECKED_MEMSET(&range_results[0], 0, sizeof(range_results));
    }

    return S2N_RESULT_OK;
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

/* Creates two threads and generates random data in those two threads as well
 * as the parent thread. Verifies that all three resulting data blobs are
 * different.
 */
static S2N_RESULT s2n_thread_test(
        S2N_RESULT (*s2n_get_random_data_cb)(struct s2n_blob *blob),
        S2N_RESULT (*s2n_get_random_data_cb_thread)(struct s2n_blob *blob))
{
    uint8_t data[RANDOM_GENERATE_DATA_SIZE];
    struct s2n_blob blob = { 0 };
    EXPECT_SUCCESS(s2n_blob_init(&blob, data, 0));
    pthread_t threads[MAX_NUMBER_OF_TEST_THREADS];

    struct random_communication thread_communication_0 = { .s2n_get_random_data_cb_1 = s2n_get_random_data_cb_thread };
    struct random_communication thread_communication_1 = { .s2n_get_random_data_cb_1 = s2n_get_random_data_cb_thread };

    /* Create two threads and have them each grab RANDOM_GENERATE_DATA_SIZE
     * bytes.
     */
    EXPECT_EQUAL(pthread_create(&threads[0], NULL, s2n_thread_test_cb, &thread_communication_0), 0);
    EXPECT_EQUAL(pthread_create(&threads[1], NULL, s2n_thread_test_cb, &thread_communication_1), 0);

    /* Wait for those threads to finish */
    EXPECT_EQUAL(pthread_join(threads[0], NULL), 0);
    EXPECT_EQUAL(pthread_join(threads[1], NULL), 0);

    /* Confirm that their random data differs from each other */
    EXPECT_BYTEARRAY_NOT_EQUAL(thread_communication_0.thread_data, thread_communication_1.thread_data, RANDOM_GENERATE_DATA_SIZE);

    /* Confirm that their random data differs from the parent thread */
    blob.size = RANDOM_GENERATE_DATA_SIZE;
    EXPECT_OK(s2n_get_random_data_cb(&blob));
    EXPECT_BYTEARRAY_NOT_EQUAL(thread_communication_0.thread_data, data, RANDOM_GENERATE_DATA_SIZE);
    EXPECT_BYTEARRAY_NOT_EQUAL(thread_communication_1.thread_data, data, RANDOM_GENERATE_DATA_SIZE);

    return S2N_RESULT_OK;
}

static void s2n_fork_test_generate_randomness(int write_fd, S2N_RESULT (*s2n_get_random_data_cb)(struct s2n_blob *blob))
{
    uint8_t data[RANDOM_GENERATE_DATA_SIZE];

    struct s2n_blob blob = { 0 };
    EXPECT_SUCCESS(s2n_blob_init(&blob, data, RANDOM_GENERATE_DATA_SIZE));
    EXPECT_OK(s2n_get_random_data_cb(&blob));

    /* Write the data we got to our pipe */
    if (write(write_fd, data, RANDOM_GENERATE_DATA_SIZE) != RANDOM_GENERATE_DATA_SIZE) {
        _exit(EXIT_FAILURE);
    }

    /* Close the pipe and exit */
    close(write_fd);
    exit(EXIT_SUCCESS);
}

/* A simple fork test. Generates random data in the parent and child, and
 * verifies that the two resulting data blobs are different.
 */
static S2N_RESULT s2n_simple_fork_test(S2N_RESULT (*s2n_get_random_data_cb)(struct s2n_blob *blob))
{
    uint8_t child_data[RANDOM_GENERATE_DATA_SIZE];
    uint8_t parent_data[RANDOM_GENERATE_DATA_SIZE];
    struct s2n_blob parent_blob = { 0 };
    EXPECT_SUCCESS(s2n_blob_init(&parent_blob, parent_data, RANDOM_GENERATE_DATA_SIZE));

    int pipes[2];
    EXPECT_SUCCESS(pipe(pipes));

    pid_t proc_id = fork();
    if (proc_id == 0) {
        /* This is the child process, close the read end of the pipe */
        EXPECT_SUCCESS(close(pipes[0]));
        s2n_fork_test_generate_randomness(pipes[1], s2n_get_random_data_cb);
    }

    /* This is the parent process, close the write end of the pipe */
    EXPECT_NOT_EQUAL(proc_id, 0);
    EXPECT_SUCCESS(close(pipes[1]));

    /* Read the child's data from the pipe */
    EXPECT_EQUAL(read(pipes[0], child_data, RANDOM_GENERATE_DATA_SIZE), RANDOM_GENERATE_DATA_SIZE);

    /* Get RANDOM_GENERATE_DATA_SIZE bytes in this parent process */
    EXPECT_OK(s2n_get_random_data_cb(&parent_blob));

    /* Confirm that their data differs from each other */
    EXPECT_BYTEARRAY_NOT_EQUAL(child_data, parent_data, RANDOM_GENERATE_DATA_SIZE);

    EXPECT_SUCCESS(close(pipes[0]));

    /* Also remember to verify that the child exited okay */
    s2n_verify_child_exit_status(proc_id, S2N_SUCCESS);

    return S2N_RESULT_OK;
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

static int s2n_random_invalid_urandom_fd_cb(struct random_test_case *test_case)
{
    struct s2n_rand_device *dev_urandom = NULL;
    EXPECT_OK(s2n_rand_get_urandom_for_test(&dev_urandom));
    EXPECT_NOT_NULL(dev_urandom);

    EXPECT_EQUAL(dev_urandom->fd, -1);

    /* Validation should fail before initialization. */
    EXPECT_ERROR(s2n_rand_device_validate(dev_urandom));

    EXPECT_SUCCESS(s2n_init());

    if (!s2n_use_libcrypto_rand()) {
        /* When using urandom, validation should succeed after initialization. */
        EXPECT_OK(s2n_rand_device_validate(dev_urandom));

        EXPECT_TRUE(dev_urandom->fd > STDERR_FILENO);

        /* Close the fd to simulate it becoming invalid */
        EXPECT_EQUAL(close(dev_urandom->fd), 0);

        /* Validation should fail when the file descriptor is closed. */
        EXPECT_ERROR(s2n_rand_device_validate(dev_urandom));

        /* Getting random data should still succeed because the fd is re-opened. */
        s2n_stack_blob(rand_data, 16, 16);
        EXPECT_OK(s2n_get_public_random_data(&rand_data));

        /* After re-open, validation should succeed again. */
        EXPECT_OK(s2n_rand_device_validate(dev_urandom));
    }

    EXPECT_SUCCESS(s2n_cleanup_final());

    return S2N_SUCCESS;
}

/* Runs the basic set of randomness tests that exercise still-existing APIs */
static int s2n_random_common_tests_cb(struct random_test_case *test_case)
{
    EXPECT_SUCCESS(s2n_init());

    /* Basic tests generating randomness */
    EXPECT_OK(s2n_basic_generate_tests());

    /* Verify we generate unique data over threads */
    EXPECT_OK(s2n_thread_test(s2n_get_public_random_data, s2n_get_public_random_data));
    EXPECT_OK(s2n_thread_test(s2n_get_private_random_data, s2n_get_private_random_data));
    EXPECT_OK(s2n_thread_test(s2n_get_public_random_data, s2n_get_private_random_data));
    EXPECT_OK(s2n_thread_test(s2n_get_private_random_data, s2n_get_public_random_data));

    /* Verify we generate unique data over forks */
    EXPECT_OK(s2n_simple_fork_test(s2n_get_public_random_data));
    EXPECT_OK(s2n_simple_fork_test(s2n_get_private_random_data));

    /* Special range function tests */
    EXPECT_OK(s2n_tests_get_range());

    EXPECT_SUCCESS(s2n_cleanup());

    return EXIT_SUCCESS;
}

struct random_test_case random_test_cases[] = {
    { "Random API: basic generate, thread, fork, and range tests.", s2n_random_common_tests_cb, CLONE_TEST_DETERMINE_AT_RUNTIME, EXIT_SUCCESS },
    { "Test destructor without s2n_init", s2n_random_noop_destructor_test_cb, CLONE_TEST_DETERMINE_AT_RUNTIME, EXIT_SUCCESS },
    /* The s2n FAIL_MSG() macro uses exit(1) not exit(EXIT_FAILURE). So, we need
     * to use 1 below and in s2n_random_test_case_failure_cb().
     */
    { "Test failure.", s2n_random_test_case_failure_cb, CLONE_TEST_DETERMINE_AT_RUNTIME, 1 },
    { "Verifies that calling s2n_cleanup_final() does not interfere with libcrypto randomness", s2n_random_rand_bytes_after_cleanup_cb, CLONE_TEST_DETERMINE_AT_RUNTIME, EXIT_SUCCESS },
    { "Test getting entropy with an invalid file descriptor", s2n_random_invalid_urandom_fd_cb, CLONE_TEST_DETERMINE_AT_RUNTIME, EXIT_SUCCESS },
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
     * whether the linked libcrypto supports RAND_priv_bytes, RAND_public_bytes,
     * or is AWS-LC.
     */
    {
#if defined(S2N_LIBCRYPTO_SUPPORTS_PRIVATE_RAND) || defined(S2N_LIBCRYPTO_SUPPORTS_PUBLIC_RAND) \
        || defined(OPENSSL_IS_AWSLC)
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
