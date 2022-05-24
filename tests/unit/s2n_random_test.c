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
#endif

#include "s2n_test.h"
#include "api/s2n.h"
#include "utils/s2n_fork_detection.h"
#include "utils/s2n_random.h"

#include <pthread.h>
#include <sys/wait.h>
#include <unistd.h>

#define MAX_NUMBER_OF_TEST_THREADS 2

#define CLONE_TEST_NO 0
#define CLONE_TEST_YES 1
#define CLONE_TEST_DETERMINE_AT_RUNTIME 2

#define RANDOM_GENERATE_DATA_SIZE 100
#define MAX_RANDOM_GENERATE_DATA_SIZE 5120

#define SLOT_NUM_0 0x00
#define SLOT_NUM_1 0x01
#define GET_PUBLIC_RANDOM_DATA 0x00
#define GET_PRIVATE_RANDOM_DATA 0x10
#define SLOT_MASK 0x0F
#define FUNC_MASK 0xF0

struct random_test_case {
    const char *test_case_label;
    int (*test_case_cb)(struct random_test_case *test_case);
    int test_case_must_pass_clone_test;
};

static uint8_t thread_data[MAX_NUMBER_OF_TEST_THREADS][RANDOM_GENERATE_DATA_SIZE];


static void s2n_verify_child_exit_status(pid_t proc_pid)
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
    /* Check that child exited with EXIT_SUCCESS. If not, this indicates
     * that an error was encountered in the unit tests executed in that
     * child process.
     */
    EXPECT_NOT_EQUAL(WIFEXITED(status), 0);
    EXPECT_EQUAL(WEXITSTATUS(status), EXIT_SUCCESS);
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

/* Try to fetch a volume of randomly generated data, every size between 1
 * and 5120 bytes
 */
static S2N_RESULT s2n_basic_pattern_tests(S2N_RESULT (*s2n_get_random_data_cb)(struct s2n_blob *blob))
{
    uint8_t bits[8] = { 0x80, 0x40, 0x20, 0x10, 0x08, 0x04, 0x02, 0x01 };
    uint8_t bit_set_run[8];
    uint8_t data[MAX_RANDOM_GENERATE_DATA_SIZE];
    struct s2n_blob blob = { .data = data }; 
    int trailing_zeros[8] = {0};

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

void * s2n_thread_test_cb(void *slot)
{
    uintptr_t slot_num = ((uintptr_t) slot) & SLOT_MASK;
    uintptr_t random_func = ((uintptr_t) slot) & FUNC_MASK;

    struct s2n_blob thread_blob = { .data = thread_data[slot_num], .size = RANDOM_GENERATE_DATA_SIZE };

    if (random_func == GET_PUBLIC_RANDOM_DATA) {
        EXPECT_OK(s2n_get_public_random_data(&thread_blob));
    }
    else if (random_func == GET_PRIVATE_RANDOM_DATA) {
        EXPECT_OK(s2n_get_private_random_data(&thread_blob));
    }
    else {
        EXPECT_SUCCESS(S2N_FAILURE);
    }

    EXPECT_OK(s2n_rand_cleanup_thread());

    return NULL;
}


static S2N_RESULT s2n_thread_test(S2N_RESULT (*s2n_get_random_data_cb)(struct s2n_blob *blob), uintptr_t thread_random_func)
{
    uint8_t data[RANDOM_GENERATE_DATA_SIZE];
    struct s2n_blob blob = { .data = data };
    pthread_t threads[MAX_NUMBER_OF_TEST_THREADS];

    /* Create two threads and have them each grab RANDOM_GENERATE_DATA_SIZE
     * bytes. The third parameter to pthread_create is packed. It containes two
     * pieces of information: where to store the random data generated in the
     * thread and which random function must be used to generate it.
     */
    EXPECT_EQUAL(pthread_create(&threads[0], NULL, s2n_thread_test_cb, (void *) (((uintptr_t) SLOT_NUM_0) | thread_random_func)), 0);
    EXPECT_EQUAL(pthread_create(&threads[1], NULL, s2n_thread_test_cb, (void *) (((uintptr_t) SLOT_NUM_1) | thread_random_func)), 0);

    /* Wait for those threads to finish */
    EXPECT_EQUAL(pthread_join(threads[0], NULL), 0);
    EXPECT_EQUAL(pthread_join(threads[1], NULL), 0);

    /* Confirm that their data differs from each other */
    EXPECT_BYTEARRAY_NOT_EQUAL(thread_data[0], thread_data[1], RANDOM_GENERATE_DATA_SIZE);

    /* Confirm that their data differs from the parent thread */
    blob.size = RANDOM_GENERATE_DATA_SIZE;
    EXPECT_OK(s2n_get_random_data_cb(&blob));
    EXPECT_BYTEARRAY_NOT_EQUAL(thread_data[0], data, RANDOM_GENERATE_DATA_SIZE);
    EXPECT_BYTEARRAY_NOT_EQUAL(thread_data[1], data, RANDOM_GENERATE_DATA_SIZE);

    return S2N_RESULT_OK;
}

static void s2n_fork_test_generate_randomness(int write_fd, S2N_RESULT (*s2n_get_random_data_cb)(struct s2n_blob *blob))
{
    uint8_t data[RANDOM_GENERATE_DATA_SIZE];

    struct s2n_blob blob = {.data = data, .size = RANDOM_GENERATE_DATA_SIZE };
    EXPECT_OK(s2n_get_random_data_cb(&blob));

    /* Write the data we got to our pipe */
    if (write(write_fd, data, RANDOM_GENERATE_DATA_SIZE) != RANDOM_GENERATE_DATA_SIZE) {
        _exit(EXIT_FAILURE);
    }

    /* Close the pipe and exit */
    close(write_fd);
    _exit(EXIT_SUCCESS);
}

static S2N_RESULT s2n_fork_test_verify_result(int *pipes, int proc_id, S2N_RESULT (*s2n_get_random_data_cb)(struct s2n_blob *blob))
{
    uint8_t child_data[RANDOM_GENERATE_DATA_SIZE];
    uint8_t parent_data[RANDOM_GENERATE_DATA_SIZE];
    struct s2n_blob parent_blob = { .data = parent_data, .size = RANDOM_GENERATE_DATA_SIZE };

    /* This is the parent process, close the write end of the pipe */
    EXPECT_SUCCESS(close(pipes[1]));

    /* Read the child's data from the pipe */
    EXPECT_EQUAL(read(pipes[0], child_data, RANDOM_GENERATE_DATA_SIZE), RANDOM_GENERATE_DATA_SIZE);

    /* Get RANDOM_GENERATE_DATA_SIZE bytes in the parent process */
    EXPECT_OK(s2n_get_random_data_cb(&parent_blob));

    /* Confirm they differ */
    EXPECT_BYTEARRAY_NOT_EQUAL(child_data, parent_data, RANDOM_GENERATE_DATA_SIZE);

    /* Clean up */
    EXPECT_SUCCESS(close(pipes[0]));

    /* Also remember to verify that the child exited okay */
    s2n_verify_child_exit_status(proc_id);

    return S2N_RESULT_OK;
}

static S2N_RESULT s2n_fork_test(S2N_RESULT (*s2n_get_random_data_cb)(struct s2n_blob *blob), uintptr_t thread_random_func)
{
    pid_t proc_id;
    int pipes[2];

    /* A simple fork test */
    EXPECT_SUCCESS(pipe(pipes));
    proc_id = fork();
    if (proc_id == 0) {
        /* This is the child process, close the read end of the pipe */
        EXPECT_SUCCESS(close(pipes[0]));
        s2n_fork_test_generate_randomness(pipes[1], s2n_get_random_data_cb);
    }
    EXPECT_OK(s2n_fork_test_verify_result(pipes, proc_id, s2n_get_random_data_cb));

    /* Create a fork, but immediately create threads in the child process. See
     * https://github.com/aws/s2n-tls/issues/3107 why this might be an issue.
     */
    EXPECT_SUCCESS(pipe(pipes));
    proc_id = fork();
    if (proc_id == 0) {
        /* This is the child process, close the read end of the pipe */
        EXPECT_SUCCESS(close(pipes[0]));
        EXPECT_OK(s2n_thread_test(s2n_get_random_data_cb, thread_random_func));
        s2n_fork_test_generate_randomness(pipes[1], s2n_get_random_data_cb);
    }
    EXPECT_OK(s2n_fork_test_verify_result(pipes, proc_id, s2n_get_random_data_cb));

    /* Create threads after gereating data in the child proces. */
    EXPECT_SUCCESS(pipe(pipes));
    proc_id = fork();
    if (proc_id == 0) {
        /* This is the child process, close the read end of the pipe */
        EXPECT_SUCCESS(close(pipes[0]));
        s2n_fork_test_generate_randomness(pipes[1], s2n_get_random_data_cb);
        EXPECT_OK(s2n_thread_test(s2n_get_random_data_cb, thread_random_func));
    }
    EXPECT_OK(s2n_fork_test_verify_result(pipes, proc_id, s2n_get_random_data_cb));

    /* Create threads in the parent process before generating data */
    EXPECT_SUCCESS(pipe(pipes));
    proc_id = fork();
    if (proc_id == 0) {
        /* This is the child process, close the read end of the pipe */
        EXPECT_SUCCESS(close(pipes[0]));
        s2n_fork_test_generate_randomness(pipes[1], s2n_get_random_data_cb);
    }
    EXPECT_OK(s2n_thread_test(s2n_get_random_data_cb, thread_random_func));
    EXPECT_OK(s2n_fork_test_verify_result(pipes, proc_id, s2n_get_random_data_cb));

    /* Basic tests in the fork */
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

static S2N_RESULT s2n_basic_generate_tests(void)
{
    uint8_t data1[RANDOM_GENERATE_DATA_SIZE];
    uint8_t data2[RANDOM_GENERATE_DATA_SIZE];
    struct s2n_blob blob1 = { .data = data1 };
    struct s2n_blob blob2 = { .data = data2 };

    /* Get two sets of data in the same process/thread, and confirm that they
     * differ
     */
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

static int s2n_common_tests(struct random_test_case *test_case)
{
    uint8_t data1[RANDOM_GENERATE_DATA_SIZE];
    uint8_t data2[RANDOM_GENERATE_DATA_SIZE];
    struct s2n_blob blob1 = { .data = data1 };
    struct s2n_blob blob2 = { .data = data2 };

    /* Get one byte of data, to make sure the pool is (almost) full */
    blob1.size = 1;
    blob2.size = 1;
    EXPECT_OK(s2n_get_public_random_data(&blob1));
    EXPECT_OK(s2n_get_private_random_data(&blob2));

    /* Verify we generate unique data over threads */
    EXPECT_OK(s2n_thread_test(s2n_get_public_random_data, GET_PUBLIC_RANDOM_DATA));
    EXPECT_OK(s2n_thread_test(s2n_get_private_random_data, GET_PRIVATE_RANDOM_DATA));
    EXPECT_OK(s2n_thread_test(s2n_get_public_random_data, GET_PRIVATE_RANDOM_DATA));
    EXPECT_OK(s2n_thread_test(s2n_get_private_random_data, GET_PUBLIC_RANDOM_DATA));

    /* Verify we generate unique data over forks */
    EXPECT_OK(s2n_fork_test(s2n_get_private_random_data, GET_PRIVATE_RANDOM_DATA));
    EXPECT_OK(s2n_fork_test(s2n_get_public_random_data, GET_PUBLIC_RANDOM_DATA));
    EXPECT_OK(s2n_fork_test(s2n_get_public_random_data, GET_PRIVATE_RANDOM_DATA));
    EXPECT_OK(s2n_fork_test(s2n_get_private_random_data, GET_PUBLIC_RANDOM_DATA));

    /* Basic tests generating randomness */
    EXPECT_OK(s2n_basic_generate_tests());

    /* Verify that there are no trivially observable patterns in the output */
    EXPECT_OK(s2n_basic_pattern_tests(s2n_get_public_random_data));
    EXPECT_OK(s2n_basic_pattern_tests(s2n_get_private_random_data));

    /* Just a sanity check and avoids cppcheck "unassignedVariable" errors.
     * In future PRs this part will be expanded.
     */
    blob1.size = RANDOM_GENERATE_DATA_SIZE;
    EXPECT_OK(s2n_get_public_random_data(&blob1));
    blob2.size = RANDOM_GENERATE_DATA_SIZE;
    EXPECT_OK(s2n_get_private_random_data(&blob2));
    EXPECT_BYTEARRAY_NOT_EQUAL(data1, data2, RANDOM_GENERATE_DATA_SIZE);

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

    return S2N_SUCCESS;
}

static int s2n_random_test_case_without_pr_cb(struct random_test_case *test_case)
{
    EXPECT_SUCCESS(s2n_init());

    POSIX_GUARD_RESULT(s2n_ignore_prediction_resistance_for_testing(true));
    EXPECT_EQUAL(s2n_common_tests(test_case), S2N_SUCCESS);
    POSIX_GUARD_RESULT(s2n_ignore_prediction_resistance_for_testing(false));

    EXPECT_SUCCESS(s2n_cleanup());

    return S2N_SUCCESS;
}

#define NUMBER_OF_RANDOM_TEST_CASES 2
struct random_test_case random_test_cases[NUMBER_OF_RANDOM_TEST_CASES] = {
    {"Random API.", s2n_random_test_case_default_cb, CLONE_TEST_DETERMINE_AT_RUNTIME},
    {"Random API without prediction resistance.", s2n_random_test_case_without_pr_cb, CLONE_TEST_DETERMINE_AT_RUNTIME},};

int main(int argc, char **argv)
{
    BEGIN_TEST_NO_INIT();

    EXPECT_TRUE(s2n_array_len(random_test_cases) == NUMBER_OF_RANDOM_TEST_CASES);

    /* Create NUMBER_OF_RANDOM_TEST_CASES number of child processes that run
     * each test case.
     *
     * Fork detection is lazily initialised on first invocation of
     * s2n_get_fork_generation_number(). Hence, it is important that childs are
     * created before calling into the fork detection code.
     */
    pid_t proc_ids[NUMBER_OF_RANDOM_TEST_CASES] = {0};

    for (size_t i = 0; i < NUMBER_OF_RANDOM_TEST_CASES; i++) {

        proc_ids[i] = fork();
        EXPECT_TRUE(proc_ids[i] >= 0);

        if (proc_ids[i] == 0) {
            /* In child */
            EXPECT_EQUAL(random_test_cases[i].test_case_cb(&random_test_cases[i]), S2N_SUCCESS);

            /* Exit code EXIT_SUCCESS means that tests in this process finished
             * successfully. Any errors would have exited the process with an
             * exit code != EXIT_SUCCESS. We verify this in the parent process.
             * Also prevents child from creating more childs.
             */
            exit(EXIT_SUCCESS);
        }
        else {
            s2n_verify_child_exit_status(proc_ids[i]);
        }
    }

    END_TEST_NO_INIT();
}
