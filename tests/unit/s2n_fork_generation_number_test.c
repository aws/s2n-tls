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

#include <pthread.h>
#include <sched.h>
#include <stdio.h>
#include <sys/param.h>
#include <sys/wait.h>

#include "s2n_test.h"
#include "utils/s2n_fork_detection.h"

#define NUMBER_OF_FGN_TEST_CASES   4
#define MAX_NUMBER_OF_TEST_THREADS 2
#define FORK_LEVEL_FOR_TESTS       2
/* Before calling s2n_get_fork_generation_number() set the argument to this
 * value to avoid any unlucky collisions
 */
#define UNEXPECTED_RETURNED_FGN 0xFF

#define CLONE_TEST_NO                   0
#define CLONE_TEST_YES                  1
#define CLONE_TEST_DETERMINE_AT_RUNTIME 2

struct fgn_test_case {
    const char *test_case_label;
    int (*test_case_cb)(struct fgn_test_case *test_case);
    int test_case_must_pass_clone_test;
};

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

static void *s2n_unit_test_thread_get_fgn(void *expected_fork_generation_number)
{
    uint64_t return_fork_generation_number = UNEXPECTED_RETURNED_FGN;
    EXPECT_OK(s2n_get_fork_generation_number(&return_fork_generation_number));
    EXPECT_EQUAL(return_fork_generation_number, *(uint64_t *) expected_fork_generation_number);

    return NULL;
}

static int s2n_unit_test_thread(uint64_t expected_fork_generation_number)
{
    pthread_t threads[MAX_NUMBER_OF_TEST_THREADS];

    for (size_t thread_index = 0; thread_index < MAX_NUMBER_OF_TEST_THREADS; thread_index++) {
        EXPECT_EQUAL(pthread_create(&threads[thread_index], NULL, &s2n_unit_test_thread_get_fgn, (void *) &expected_fork_generation_number), 0);
    }

    /* Wait for all threads to finish */
    for (size_t thread_index = 0; thread_index < MAX_NUMBER_OF_TEST_THREADS; thread_index++) {
        pthread_join(threads[thread_index], NULL);
    }

    return S2N_SUCCESS;
}

static int s2n_unit_test_fork(uint64_t parent_process_fgn, int fork_level)
{
    pid_t proc_pid = fork();
    EXPECT_TRUE(proc_pid >= 0);

    fork_level = fork_level - 1;

    if (proc_pid == 0) {
        /* In child */
        uint64_t return_fork_generation_number = UNEXPECTED_RETURNED_FGN;
        EXPECT_OK(s2n_get_fork_generation_number(&return_fork_generation_number));
        EXPECT_EQUAL(return_fork_generation_number, parent_process_fgn + 1);

        /* Verify stability */
        return_fork_generation_number = UNEXPECTED_RETURNED_FGN;
        EXPECT_OK(s2n_get_fork_generation_number(&return_fork_generation_number));
        EXPECT_EQUAL(return_fork_generation_number, parent_process_fgn + 1);

        /* Verify in threads */
        EXPECT_EQUAL(s2n_unit_test_thread(return_fork_generation_number), S2N_SUCCESS);

        if (fork_level > 0) {
            /* Fork again and verify fork generation number */
            EXPECT_EQUAL(s2n_unit_test_fork(parent_process_fgn + 1, fork_level), S2N_SUCCESS);
        }

        /* Exit code EXIT_SUCCESS means that tests in this process finished
         * successfully. Any errors would have exited the process with an
         * exit code != EXIT_SUCCESS. We verify this in the parent process.
         */
        exit(EXIT_SUCCESS);
    } else {
        s2n_verify_child_exit_status(proc_pid);

        /* Verify stability */
        uint64_t return_fork_generation_number = UNEXPECTED_RETURNED_FGN;
        EXPECT_OK(s2n_get_fork_generation_number(&return_fork_generation_number));
        EXPECT_EQUAL(return_fork_generation_number, parent_process_fgn);
    }

    return S2N_SUCCESS;
}

/* Similar test to unit_test_fork() but verify in threads first */
static int s2n_unit_test_fork_check_threads_first(uint64_t parent_process_fgn)
{
    pid_t proc_pid = fork();
    EXPECT_TRUE(proc_pid >= 0);

    if (proc_pid == 0) {
        /* In child. Verify threads first. */
        EXPECT_EQUAL(s2n_unit_test_thread(parent_process_fgn + 1), S2N_SUCCESS);

        /* Then in the thread spawned when forking */
        uint64_t return_fork_generation_number = UNEXPECTED_RETURNED_FGN;
        EXPECT_OK(s2n_get_fork_generation_number(&return_fork_generation_number));
        EXPECT_EQUAL(return_fork_generation_number, parent_process_fgn + 1);

        /* Verify stability */
        return_fork_generation_number = UNEXPECTED_RETURNED_FGN;
        EXPECT_OK(s2n_get_fork_generation_number(&return_fork_generation_number));
        EXPECT_EQUAL(return_fork_generation_number, parent_process_fgn + 1);

        /* Exit code EXIT_SUCCESS means that tests in this process finished
         * successfully. Any errors would have exited the process with an
         * exit code != EXIT_SUCCESS. We verify this in the parent process.
         */
        exit(EXIT_SUCCESS);
    } else {
        s2n_verify_child_exit_status(proc_pid);

        /* Verify stability */
        uint64_t return_fork_generation_number = UNEXPECTED_RETURNED_FGN;
        EXPECT_OK(s2n_get_fork_generation_number(&return_fork_generation_number));
        EXPECT_EQUAL(return_fork_generation_number, parent_process_fgn);
    }

    return S2N_SUCCESS;
}

static int s2n_unit_test_clone_child_process(void *parent_process_fgn)
{
    /* In child */
    uint64_t local_parent_process_fgn = *(uint64_t *) parent_process_fgn;
    uint64_t return_fork_generation_number = UNEXPECTED_RETURNED_FGN;
    EXPECT_OK(s2n_get_fork_generation_number(&return_fork_generation_number));
    EXPECT_EQUAL(return_fork_generation_number, local_parent_process_fgn + 1);

    /* Verify stability */
    return_fork_generation_number = UNEXPECTED_RETURNED_FGN;
    EXPECT_OK(s2n_get_fork_generation_number(&return_fork_generation_number));
    EXPECT_EQUAL(return_fork_generation_number, local_parent_process_fgn + 1);

    /* Verify in threads */
    EXPECT_EQUAL(s2n_unit_test_thread(return_fork_generation_number), S2N_SUCCESS);

    /* This translates to the exit code for this child process */
    return EXIT_SUCCESS;
}

#define PROCESS_CHILD_STACK_SIZE (1024 * 1024) /* Suggested by clone() man page... */
static int s2n_unit_test_clone(uint64_t parent_process_fgn)
{
#if defined(S2N_CLONE_SUPPORTED)
    /* Verify stability */
    uint64_t return_fork_generation_number = UNEXPECTED_RETURNED_FGN;
    EXPECT_OK(s2n_get_fork_generation_number(&return_fork_generation_number));
    EXPECT_EQUAL(return_fork_generation_number, parent_process_fgn);

    /* Use stack memory for this... We don't exit unit_test_clone() before this
     * memory has served its purpose.
     * Why? Using dynamically allocated memory causes Valgrind to squat on the
     * allocated memory when the child process exists.
     */
    char process_child_stack[PROCESS_CHILD_STACK_SIZE];
    EXPECT_NOT_NULL(process_child_stack);

    int proc_pid = clone(s2n_unit_test_clone_child_process, (void *) (process_child_stack + PROCESS_CHILD_STACK_SIZE), 0, (void *) &return_fork_generation_number);
    EXPECT_NOT_EQUAL(proc_pid, -1);

    s2n_verify_child_exit_status(proc_pid);

    /* Verify stability */
    return_fork_generation_number = UNEXPECTED_RETURNED_FGN;
    EXPECT_OK(s2n_get_fork_generation_number(&return_fork_generation_number));
    EXPECT_EQUAL(return_fork_generation_number, parent_process_fgn);
#endif

    return S2N_SUCCESS;
}

static int s2n_unit_tests_common(struct fgn_test_case *test_case)
{
    uint64_t return_fork_generation_number = 0;

    EXPECT_OK(s2n_get_fork_generation_number(&return_fork_generation_number));
    EXPECT_EQUAL(return_fork_generation_number, 0);

    /* Should be idempotent if no fork event occurred */
    return_fork_generation_number = UNEXPECTED_RETURNED_FGN;
    EXPECT_OK(s2n_get_fork_generation_number(&return_fork_generation_number));
    EXPECT_EQUAL(return_fork_generation_number, 0);

    /* Should be idempotent in threaded environment as well */
    EXPECT_EQUAL(s2n_unit_test_thread(return_fork_generation_number), S2N_SUCCESS);

    /* Cached FGN should increment if a fork event occurs */
    EXPECT_EQUAL(s2n_unit_test_fork(return_fork_generation_number, FORK_LEVEL_FOR_TESTS), S2N_SUCCESS);
    EXPECT_EQUAL(s2n_unit_test_fork_check_threads_first(return_fork_generation_number), S2N_SUCCESS);

    /* Some fork detection mechanisms can also detect forks through clone() */
    if (test_case->test_case_must_pass_clone_test == CLONE_TEST_YES) {
        EXPECT_EQUAL((s2n_is_madv_wipeonfork_supported() == true) || (s2n_is_map_inherit_zero_supported() == true), true);
        EXPECT_EQUAL(s2n_unit_test_clone(return_fork_generation_number), S2N_SUCCESS);
    } else if (test_case->test_case_must_pass_clone_test == CLONE_TEST_DETERMINE_AT_RUNTIME) {
        if ((s2n_is_madv_wipeonfork_supported() == true) || (s2n_is_map_inherit_zero_supported() == true)) {
            EXPECT_EQUAL(s2n_unit_test_clone(return_fork_generation_number), S2N_SUCCESS);
        }
    }

    return S2N_SUCCESS;
}

static int s2n_test_case_default_cb(struct fgn_test_case *test_case)
{
    EXPECT_SUCCESS(s2n_init());

    EXPECT_EQUAL(s2n_unit_tests_common(test_case), S2N_SUCCESS);

    EXPECT_SUCCESS(s2n_cleanup());

    return S2N_SUCCESS;
}

static int s2n_test_case_pthread_atfork_cb(struct fgn_test_case *test_case)
{
    if (s2n_is_pthread_atfork_supported() == false) {
        TEST_DEBUG_PRINT("s2n_fork_generation_number_test.c test case not supported. Skipping.\nTest case: %s\n", test_case->test_case_label);
        return S2N_SUCCESS;
    }
    POSIX_GUARD_RESULT(s2n_ignore_wipeonfork_and_inherit_zero_for_testing());

    EXPECT_SUCCESS(s2n_init());

    EXPECT_EQUAL(s2n_unit_tests_common(test_case), S2N_SUCCESS);

    EXPECT_SUCCESS(s2n_cleanup());

    return S2N_SUCCESS;
}

static int s2n_test_case_madv_wipeonfork_cb(struct fgn_test_case *test_case)
{
    if (s2n_is_madv_wipeonfork_supported() == false) {
        TEST_DEBUG_PRINT("s2n_fork_generation_number_test.c test case not supported. Skipping.\nTest case: %s\n", test_case->test_case_label);
        return S2N_SUCCESS;
    }
    POSIX_GUARD_RESULT(s2n_ignore_pthread_atfork_for_testing());

    EXPECT_SUCCESS(s2n_init());

    EXPECT_EQUAL(s2n_unit_tests_common(test_case), S2N_SUCCESS);

    EXPECT_SUCCESS(s2n_cleanup());

    return S2N_SUCCESS;
}

static int s2n_test_case_map_inherit_zero_cb(struct fgn_test_case *test_case)
{
    if (s2n_is_map_inherit_zero_supported() == false) {
        TEST_DEBUG_PRINT("s2n_fork_generation_number_test.c test case not supported. Skipping.\nTest case: %s\n", test_case->test_case_label);
        return S2N_SUCCESS;
    }
    POSIX_GUARD_RESULT(s2n_ignore_pthread_atfork_for_testing());

    EXPECT_SUCCESS(s2n_init());

    EXPECT_EQUAL(s2n_unit_tests_common(test_case), S2N_SUCCESS);

    EXPECT_SUCCESS(s2n_cleanup());

    return S2N_SUCCESS;
}

struct fgn_test_case fgn_test_cases[NUMBER_OF_FGN_TEST_CASES] = {
    { "Default fork detect mechanisms.", s2n_test_case_default_cb, CLONE_TEST_DETERMINE_AT_RUNTIME },
    { "Only pthread_atfork fork detection mechanism.", s2n_test_case_pthread_atfork_cb, CLONE_TEST_NO },
    { "Only madv_wipeonfork fork detection mechanism.", s2n_test_case_madv_wipeonfork_cb, CLONE_TEST_YES },
    { "Only map_inherit_zero fork detection mechanism.", s2n_test_case_map_inherit_zero_cb, CLONE_TEST_YES }
};

int main(int argc, char **argv)
{
    BEGIN_TEST_NO_INIT();

    EXPECT_TRUE(s2n_array_len(fgn_test_cases) == NUMBER_OF_FGN_TEST_CASES);

/* Test: FreeBSD >= 12.0 should use map_inherit_zero */
#ifdef __FreeBSD__
    #ifndef __FreeBSD_version
        #error "Unknown FreeBSD version"
    #endif

    #if __FreeBSD_version >= 1200000
    EXPECT_TRUE(s2n_is_map_inherit_zero_supported());
    #endif
#endif

    /* Create NUMBER_OF_FGN_TEST_CASES number of child processes that run each
     * test case.
     *
     * Fork detection is lazily initialised on first invocation of
     * s2n_get_fork_generation_number(). Hence, it is important that childs are
     * created before calling into the fork detection code.
     */
    pid_t proc_pids[NUMBER_OF_FGN_TEST_CASES] = { 0 };

    for (size_t i = 0; i < NUMBER_OF_FGN_TEST_CASES; i++) {
        proc_pids[i] = fork();
        EXPECT_TRUE(proc_pids[i] >= 0);

        if (proc_pids[i] == 0) {
            /* In child */
            EXPECT_EQUAL(fgn_test_cases[i].test_case_cb(&fgn_test_cases[i]), S2N_SUCCESS);

            /* Exit code EXIT_SUCCESS means that tests in this process finished
             * successfully. Any errors would have exited the process with an
             * exit code != EXIT_SUCCESS. We verify this in the parent process.
             * Also prevents child from creating more childs.
             */
            exit(EXIT_SUCCESS);
        } else {
            s2n_verify_child_exit_status(proc_pids[i]);
        }
    }

    END_TEST_NO_INIT();
}
