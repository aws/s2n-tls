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
#include "s2n_test.h"
#include "utils/s2n_fork_detection.h"

#define MAX_NUMBER_OF_TEST_THREADS 2

#define CLONE_TEST_NO                   0
#define CLONE_TEST_YES                  1
#define CLONE_TEST_DETERMINE_AT_RUNTIME 2

#define RANDOM_GENERATE_DATA_SIZE     100
#define MAX_RANDOM_GENERATE_DATA_SIZE 5120

#define NUMBER_OF_BOUNDS               10
#define NUMBER_OF_RANGE_FUNCTION_CALLS 200
#define MAX_REPEATED_OUTPUT            4

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
#if defined(S2N_CLONE_SUPPORTED)
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

static int s2n_init_cb(void)
{
    return S2N_SUCCESS;
}

static int s2n_cleanup_cb(void)
{
    return S2N_SUCCESS;
}

static int s2n_entropy_cb(void *ptr, uint32_t size)
{
    return S2N_SUCCESS;
}

/* Generates random data (every size between 1 and 5120 bytes) and performs
 * basic pattern tests on the resulting output
 */
static S2N_RESULT s2n_basic_pattern_tests(S2N_RESULT (*s2n_get_random_data_cb)(struct s2n_blob *blob))
{
    uint8_t bits[8] = { 0x80, 0x40, 0x20, 0x10, 0x08, 0x04, 0x02, 0x01 };
    uint8_t bit_set_run[8];
    uint8_t data[MAX_RANDOM_GENERATE_DATA_SIZE];
    struct s2n_blob blob = { 0 };
    EXPECT_SUCCESS(s2n_blob_init(&blob, data, 0));
    int trailing_zeros[8] = { 0 };

    for (int size = 0; size < MAX_RANDOM_GENERATE_DATA_SIZE; size++) {
        blob.size = size;
        EXPECT_OK(s2n_get_random_data_cb(&blob));

        if (size >= 64) {
            /* Set the run counts to 0 */
            memset(bit_set_run, 0, 8);

            /* Apply 8 monobit tests to the data. Basically, we're
             * looking for successive runs where a given bit is set.
             * If a run exists with any particular bit 64 times in
             * a row, then the data doesn't look randomly generated.
             */
            for (int j = 0; j < size; j++) {
                for (int k = 0; k < 8; k++) {
                    if (data[j] & bits[k]) {
                        bit_set_run[k]++;

                        if (j >= 64) {
                            RESULT_ENSURE_LT(bit_set_run[k], 64);
                        }
                    } else {
                        bit_set_run[k] = 0;
                    }
                }
            }
        }

        /* A common mistake in array filling leaves the last bytes zero
         * depending on the length
         */
        int remainder = size % 8;
        int non_zero_found = 0;
        for (int t = size - remainder; t < size; t++) {
            non_zero_found |= data[t];
        }
        if (!non_zero_found) {
            trailing_zeros[remainder]++;
        }
    }
    for (int t = 1; t < 8; t++) {
        RESULT_ENSURE_LT(trailing_zeros[t], 5120 / 16);
    }

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

    EXPECT_OK(s2n_rand_cleanup_thread());

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

static S2N_RESULT s2n_fork_test_verify_result(int *pipes, int proc_id, S2N_RESULT (*s2n_get_random_data_cb)(struct s2n_blob *blob))
{
    uint8_t child_data[RANDOM_GENERATE_DATA_SIZE];
    uint8_t parent_data[RANDOM_GENERATE_DATA_SIZE];
    struct s2n_blob parent_blob = { 0 };
    EXPECT_SUCCESS(s2n_blob_init(&parent_blob, parent_data, RANDOM_GENERATE_DATA_SIZE));

    /* Quickly verify we are in the parent process and not the child */
    EXPECT_NOT_EQUAL(proc_id, 0);

    /* This is the parent process, close the write end of the pipe */
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

/* This function lists a number of stanzas performing various random data
 * generation tests. Each stanza goes through a different combination of forking
 * a process and threading. Each stanza must end with
 * s2n_fork_test_verify_result() to verify the result and the exit code of the
 * child process.
 */
static S2N_RESULT s2n_fork_test(
        S2N_RESULT (*s2n_get_random_data_cb)(struct s2n_blob *blob),
        S2N_RESULT (*s2n_get_random_data_cb_thread)(struct s2n_blob *blob))
{
    pid_t proc_id;
    int pipes[2];

    /* A simple fork test. Generates random data in the parent and child, and
     * verifies that the two resulting data blobs are different.
     */
    EXPECT_SUCCESS(pipe(pipes));
    proc_id = fork();
    if (proc_id == 0) {
        /* This is the child process, close the read end of the pipe */
        EXPECT_SUCCESS(close(pipes[0]));
        s2n_fork_test_generate_randomness(pipes[1], s2n_get_random_data_cb);
    }
    EXPECT_OK(s2n_fork_test_verify_result(pipes, proc_id, s2n_get_random_data_cb));

    /* Creates a fork, but immediately creates threads in the child process. See
     * https://github.com/aws/s2n-tls/issues/3107 why this might be an issue.
     */
    EXPECT_SUCCESS(pipe(pipes));
    proc_id = fork();
    if (proc_id == 0) {
        /* This is the child process, close the read end of the pipe */
        EXPECT_SUCCESS(close(pipes[0]));
        EXPECT_OK(s2n_thread_test(s2n_get_random_data_cb, s2n_get_random_data_cb_thread));
        s2n_fork_test_generate_randomness(pipes[1], s2n_get_random_data_cb);
    }
    EXPECT_OK(s2n_fork_test_verify_result(pipes, proc_id, s2n_get_random_data_cb));

    /* Creates threads and generates random data but only after generating
     * random data in the child process */
    EXPECT_SUCCESS(pipe(pipes));
    proc_id = fork();
    if (proc_id == 0) {
        /* This is the child process, close the read end of the pipe */
        EXPECT_SUCCESS(close(pipes[0]));
        s2n_fork_test_generate_randomness(pipes[1], s2n_get_random_data_cb);
        EXPECT_OK(s2n_thread_test(s2n_get_random_data_cb, s2n_get_random_data_cb_thread));
    }
    EXPECT_OK(s2n_fork_test_verify_result(pipes, proc_id, s2n_get_random_data_cb));

    /* Creates threads in the parent process before generating random data */
    EXPECT_SUCCESS(pipe(pipes));
    proc_id = fork();
    if (proc_id == 0) {
        /* This is the child process, close the read end of the pipe */
        EXPECT_SUCCESS(close(pipes[0]));
        s2n_fork_test_generate_randomness(pipes[1], s2n_get_random_data_cb);
    }
    EXPECT_OK(s2n_thread_test(s2n_get_random_data_cb, s2n_get_random_data_cb_thread));
    EXPECT_OK(s2n_fork_test_verify_result(pipes, proc_id, s2n_get_random_data_cb));

    /* Basic tests in the child process */
    EXPECT_SUCCESS(pipe(pipes));
    proc_id = fork();
    if (proc_id == 0) {
        /* This is the child process, close the read end of the pipe */
        EXPECT_SUCCESS(close(pipes[0]));
        EXPECT_OK(s2n_basic_pattern_tests(s2n_get_random_data_cb));
        s2n_fork_test_generate_randomness(pipes[1], s2n_get_random_data_cb);
    }
    EXPECT_OK(s2n_fork_test_verify_result(pipes, proc_id, s2n_get_random_data_cb));

    return S2N_RESULT_OK;
}

static int s2n_clone_tests_child_process(void *ipc)
{
    struct random_communication *ipc_ptr = (struct random_communication *) ipc;

    /* This is the child process, close the read end of the pipe */
    EXPECT_SUCCESS(close((int) ipc_ptr->pipes[0]));
    EXPECT_NOT_NULL(ipc_ptr->s2n_get_random_data_cb_2);
    s2n_fork_test_generate_randomness((int) ipc_ptr->pipes[1], ipc_ptr->s2n_get_random_data_cb_2);

    /* s2n_fork_test_generate_randomness() will exit. But we need a return
     * statement because we are in a non-void return type function. */
    return EXIT_SUCCESS;
}

#define PROCESS_CHILD_STACK_SIZE (1024 * 1024) /* Suggested by clone() man page... */
static S2N_RESULT s2n_clone_tests(
        S2N_RESULT (*s2n_get_random_data_cb)(struct s2n_blob *blob),
        S2N_RESULT (*s2n_get_random_data_cb_clone)(struct s2n_blob *blob))
{
#if defined(S2N_CLONE_SUPPORTED)

    int proc_id;
    int pipes[2];

    EXPECT_SUCCESS(pipe(pipes));

    /* Use stack memory for this... We don't exit unit_test_clone() before this
     * memory has served its purpose.
     * Why? Using dynamically allocated memory causes Valgrind to squat on the
     * allocated memory when the child process exists.
     */
    char process_child_stack[PROCESS_CHILD_STACK_SIZE];
    EXPECT_NOT_NULL(process_child_stack);

    struct random_communication ipc = {
        .s2n_get_random_data_cb_1 = s2n_get_random_data_cb,
        .s2n_get_random_data_cb_2 = s2n_get_random_data_cb_clone,
        .pipes = (int *) pipes
    };

    proc_id = clone(s2n_clone_tests_child_process, (void *) (process_child_stack + PROCESS_CHILD_STACK_SIZE), 0, (void *) &ipc);
    EXPECT_NOT_EQUAL(proc_id, -1);
    EXPECT_OK(s2n_fork_test_verify_result(pipes, proc_id, ipc.s2n_get_random_data_cb_1));
#endif

    return S2N_RESULT_OK;
}

static S2N_RESULT s2n_execute_clone_tests(void)
{
    EXPECT_OK(s2n_clone_tests(s2n_get_public_random_data, s2n_get_public_random_data));
    EXPECT_OK(s2n_clone_tests(s2n_get_private_random_data, s2n_get_private_random_data));
    EXPECT_OK(s2n_clone_tests(s2n_get_public_random_data, s2n_get_private_random_data));
    EXPECT_OK(s2n_clone_tests(s2n_get_private_random_data, s2n_get_public_random_data));

    return S2N_RESULT_OK;
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

static S2N_RESULT s2n_random_implementation_test(void)
{
    uint8_t random_data[RANDOM_GENERATE_DATA_SIZE] = { 0 };
    struct s2n_blob blob = { 0 };
    EXPECT_SUCCESS(s2n_blob_init(&blob, random_data, sizeof(random_data)));

    uint64_t previous_public_bytes_used = 0;
    EXPECT_OK(s2n_get_public_random_bytes_used(&previous_public_bytes_used));
    uint64_t previous_private_bytes_used = 0;
    EXPECT_OK(s2n_get_private_random_bytes_used(&previous_private_bytes_used));

    EXPECT_OK(s2n_get_public_random_data(&blob));
    EXPECT_OK(s2n_get_private_random_data(&blob));

    uint64_t public_bytes_used = 0;
    EXPECT_OK(s2n_get_public_random_bytes_used(&public_bytes_used));
    uint64_t private_bytes_used = 0;
    EXPECT_OK(s2n_get_private_random_bytes_used(&private_bytes_used));

    if (s2n_is_in_fips_mode()) {
        /* The libcrypto random implementation should be used when operating in FIPS mode, so
         * the bytes used in the custom DRBG state should not have changed.
         */
        EXPECT_EQUAL(public_bytes_used, previous_public_bytes_used);
        EXPECT_EQUAL(private_bytes_used, previous_public_bytes_used);
    } else {
        EXPECT_TRUE(public_bytes_used > previous_public_bytes_used);
        EXPECT_TRUE(private_bytes_used > previous_private_bytes_used);
    }

    return S2N_RESULT_OK;
}

/* A collection of tests executed for each test dimension */
static int s2n_common_tests(struct random_test_case *test_case)
{
    uint8_t data1[RANDOM_GENERATE_DATA_SIZE];
    uint8_t data2[RANDOM_GENERATE_DATA_SIZE];
    struct s2n_blob blob1 = { 0 };
    EXPECT_SUCCESS(s2n_blob_init(&blob1, data1, 0));
    struct s2n_blob blob2 = { 0 };
    EXPECT_SUCCESS(s2n_blob_init(&blob2, data2, 0));
    int64_t bound = 0;
    uint64_t output = 0;

    /* Get one byte of data, to make sure the pool is (almost) full */
    blob1.size = 1;
    blob2.size = 1;
    EXPECT_OK(s2n_get_public_random_data(&blob1));
    EXPECT_OK(s2n_get_private_random_data(&blob2));

    /* Verify we generate unique data over threads */
    EXPECT_OK(s2n_thread_test(s2n_get_public_random_data, s2n_get_public_random_data));
    EXPECT_OK(s2n_thread_test(s2n_get_private_random_data, s2n_get_private_random_data));
    EXPECT_OK(s2n_thread_test(s2n_get_public_random_data, s2n_get_private_random_data));
    EXPECT_OK(s2n_thread_test(s2n_get_private_random_data, s2n_get_public_random_data));

    /* Verify we generate unique data over forks */
    EXPECT_OK(s2n_fork_test(s2n_get_private_random_data, s2n_get_private_random_data));
    EXPECT_OK(s2n_fork_test(s2n_get_public_random_data, s2n_get_public_random_data));
    EXPECT_OK(s2n_fork_test(s2n_get_public_random_data, s2n_get_private_random_data));
    EXPECT_OK(s2n_fork_test(s2n_get_private_random_data, s2n_get_public_random_data));

    /* Some fork detection mechanisms can also detect forks through clone().
     * s2n_is_X_supported() only determines whether the system runtime
     * environment supports fork detection method X. The function is not aware
     * of the test case which is running. So, we need the CLONE_* tags to
     * determine whether the clone test should run or not since some test cases
     * disables the fork detection methods that can detect forks through clone()
     */
    if (test_case->test_case_must_pass_clone_test == CLONE_TEST_YES) {
        EXPECT_EQUAL(s2n_is_madv_wipeonfork_supported() || s2n_is_map_inherit_zero_supported(), true);
        EXPECT_OK(s2n_execute_clone_tests());
    } else if (test_case->test_case_must_pass_clone_test == CLONE_TEST_DETERMINE_AT_RUNTIME) {
        if (s2n_is_madv_wipeonfork_supported() || s2n_is_map_inherit_zero_supported()) {
            EXPECT_OK(s2n_execute_clone_tests());
        }
    }

    /* Basic tests generating randomness */
    EXPECT_OK(s2n_basic_generate_tests());

    /* Test that the correct random implementation is used */
    EXPECT_OK(s2n_random_implementation_test());

    /* Verify that there are no trivially observable patterns in the output */
    EXPECT_OK(s2n_basic_pattern_tests(s2n_get_public_random_data));
    EXPECT_OK(s2n_basic_pattern_tests(s2n_get_private_random_data));

    /* Special range function tests */
    EXPECT_OK(s2n_tests_get_range());

    /* Try to cleanup in the current thread and gather random data again for
     * each of the public functions. We did not call s2n_rand_cleanup(), so this
     * should still work properly.
     */
    EXPECT_OK(s2n_rand_cleanup_thread());
    blob1.size = RANDOM_GENERATE_DATA_SIZE;
    EXPECT_OK(s2n_get_public_random_data(&blob1));
    EXPECT_OK(s2n_basic_generate_tests());

    EXPECT_OK(s2n_rand_cleanup_thread());
    blob2.size = RANDOM_GENERATE_DATA_SIZE;
    EXPECT_OK(s2n_get_private_random_data(&blob2));
    EXPECT_OK(s2n_basic_generate_tests());

    bound = RANDOM_GENERATE_DATA_SIZE;
    EXPECT_OK(s2n_rand_cleanup_thread());
    EXPECT_OK(s2n_public_random(bound, &output));
    EXPECT_TRUE(output < bound);

    /* Just a sanity check */
    EXPECT_BYTEARRAY_NOT_EQUAL(data1, data2, RANDOM_GENERATE_DATA_SIZE);

    /* Verify that fork detection also works if we fork before initializing
     * the drbgs
     */
    EXPECT_OK(s2n_rand_cleanup_thread());
    EXPECT_OK(s2n_fork_test(s2n_get_private_random_data, s2n_get_private_random_data));
    EXPECT_OK(s2n_rand_cleanup_thread());
    EXPECT_OK(s2n_fork_test(s2n_get_public_random_data, s2n_get_public_random_data));

    /* Verify that threading before initializing doesn't cause any issues */
    EXPECT_OK(s2n_rand_cleanup_thread());
    EXPECT_OK(s2n_thread_test(s2n_get_public_random_data, s2n_get_public_random_data));
    EXPECT_OK(s2n_rand_cleanup_thread());
    EXPECT_OK(s2n_thread_test(s2n_get_private_random_data, s2n_get_private_random_data));

    return S2N_SUCCESS;
}

static int s2n_random_test_case_default_cb(struct random_test_case *test_case)
{
    EXPECT_SUCCESS(s2n_init());

    /* Verify that randomness callbacks can't be set to NULL */
    EXPECT_FAILURE(s2n_rand_set_callbacks(NULL, s2n_cleanup_cb, s2n_entropy_cb, s2n_entropy_cb));
    EXPECT_FAILURE(s2n_rand_set_callbacks(s2n_init_cb, NULL, s2n_entropy_cb, s2n_entropy_cb));
    EXPECT_FAILURE(s2n_rand_set_callbacks(s2n_init_cb, s2n_cleanup_cb, NULL, s2n_entropy_cb));
    EXPECT_FAILURE(s2n_rand_set_callbacks(s2n_init_cb, s2n_cleanup_cb, s2n_entropy_cb, NULL));

    EXPECT_EQUAL(s2n_common_tests(test_case), S2N_SUCCESS);

    EXPECT_SUCCESS(s2n_cleanup());

    return EXIT_SUCCESS;
}

/* Test case that turns off prediction resistance */
static int s2n_random_test_case_without_pr_cb(struct random_test_case *test_case)
{
    EXPECT_SUCCESS(s2n_init());

    POSIX_GUARD_RESULT(s2n_ignore_prediction_resistance_for_testing(true));
    EXPECT_EQUAL(s2n_common_tests(test_case), S2N_SUCCESS);
    POSIX_GUARD_RESULT(s2n_ignore_prediction_resistance_for_testing(false));

    EXPECT_SUCCESS(s2n_cleanup());

    return EXIT_SUCCESS;
}

/* Test case that turns off prediction resistance and all fork detection
 * mechanisms except pthread_at_fork()
 */
static int s2n_random_test_case_without_pr_pthread_atfork_cb(struct random_test_case *test_case)
{
    if (s2n_is_pthread_atfork_supported() == false) {
        TEST_DEBUG_PRINT("s2n_random_test.c test case not supported. Skipping.\nTest case: %s\n", test_case->test_case_label);
        return S2N_SUCCESS;
    }

    POSIX_GUARD_RESULT(s2n_ignore_wipeonfork_and_inherit_zero_for_testing());

    EXPECT_SUCCESS(s2n_init());

    POSIX_GUARD_RESULT(s2n_ignore_prediction_resistance_for_testing(true));
    EXPECT_EQUAL(s2n_common_tests(test_case), S2N_SUCCESS);
    POSIX_GUARD_RESULT(s2n_ignore_prediction_resistance_for_testing(false));

    EXPECT_SUCCESS(s2n_cleanup());

    return EXIT_SUCCESS;
}

static int s2n_random_test_case_without_pr_madv_wipeonfork_cb(struct random_test_case *test_case)
{
    if (s2n_is_madv_wipeonfork_supported() == false) {
        TEST_DEBUG_PRINT("s2n_random_test.c test case not supported. Skipping.\nTest case: %s\n", test_case->test_case_label);
        return S2N_SUCCESS;
    }

    POSIX_GUARD_RESULT(s2n_ignore_pthread_atfork_for_testing());

    EXPECT_SUCCESS(s2n_init());

    POSIX_GUARD_RESULT(s2n_ignore_prediction_resistance_for_testing(true));
    EXPECT_EQUAL(s2n_common_tests(test_case), S2N_SUCCESS);
    POSIX_GUARD_RESULT(s2n_ignore_prediction_resistance_for_testing(false));

    EXPECT_SUCCESS(s2n_cleanup());

    return S2N_SUCCESS;
}

static int s2n_random_test_case_without_pr_map_inherit_zero_cb(struct random_test_case *test_case)
{
    if (s2n_is_map_inherit_zero_supported() == false) {
        TEST_DEBUG_PRINT("s2n_random_test.c test case not supported. Skipping.\nTest case: %s\n", test_case->test_case_label);
        return S2N_SUCCESS;
    }

    POSIX_GUARD_RESULT(s2n_ignore_pthread_atfork_for_testing());

    EXPECT_SUCCESS(s2n_init());

    POSIX_GUARD_RESULT(s2n_ignore_prediction_resistance_for_testing(true));
    EXPECT_EQUAL(s2n_common_tests(test_case), S2N_SUCCESS);
    POSIX_GUARD_RESULT(s2n_ignore_prediction_resistance_for_testing(false));

    EXPECT_SUCCESS(s2n_cleanup());

    return S2N_SUCCESS;
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
    s2n_disable_atexit();
    EXPECT_SUCCESS(s2n_init());
    EXPECT_SUCCESS(s2n_cleanup());

    unsigned char rndbytes[16];
    EXPECT_EQUAL(RAND_bytes(rndbytes, sizeof(rndbytes)), 1);

    return S2N_SUCCESS;
}

struct random_test_case random_test_cases[] = {
    { "Random API.", s2n_random_test_case_default_cb, CLONE_TEST_DETERMINE_AT_RUNTIME, EXIT_SUCCESS },
    { "Random API without prediction resistance.", s2n_random_test_case_without_pr_cb, CLONE_TEST_DETERMINE_AT_RUNTIME, EXIT_SUCCESS },
    { "Random API without prediction resistance and with only pthread_atfork fork detection mechanism.", s2n_random_test_case_without_pr_pthread_atfork_cb, CLONE_TEST_NO, EXIT_SUCCESS },
    { "Random API without prediction resistance and with only madv_wipeonfork fork detection mechanism.", s2n_random_test_case_without_pr_madv_wipeonfork_cb, CLONE_TEST_YES, EXIT_SUCCESS },
    { "Random API without prediction resistance and with only map_inheret_zero fork detection mechanism.", s2n_random_test_case_without_pr_map_inherit_zero_cb, CLONE_TEST_YES, EXIT_SUCCESS },
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

    /* For each test case, creates a child process that runs the test case.
     *
     * Fork detection is lazily initialised on first invocation of
     * s2n_get_fork_generation_number(). Hence, it is important that children
     * are created before calling into the fork detection code.
     */
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
