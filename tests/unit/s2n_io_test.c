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

#include "utils/s2n_io.h"

#include <sys/wait.h>

#include "s2n_test.h"
#include "tests/testlib/s2n_testlib.h"

#define S2N_TEST_SIGNAL  SIGUSR1
#define S2N_TEST_SUCCESS 123

static int s2n_test_mocked_interrupt(uint8_t n_times, uint8_t *counter)
{
    if (*counter < n_times) {
        (*counter)++;

        errno = EINTR;
        return -1;
    }
    return S2N_TEST_SUCCESS;
}

static int s2n_test_real_interrupt(int fd, uint8_t n_times, uint8_t *counter)
{
    if (*counter < n_times) {
        (*counter)++;

        /* There is no data being written to fd,
         * so this will block indefinitely unless interrupted.
         */
        uint8_t buffer = 0;
        int r = read(fd, &buffer, 1);
        EXPECT_TRUE(r < 0);
        EXPECT_EQUAL(errno, EINTR);
        return r;
    }
    return S2N_TEST_SUCCESS;
}

static void s2n_test_sig_handler(int signum)
{
    EXPECT_EQUAL(signum, S2N_TEST_SIGNAL);
}

static int s2n_fail_without_errno(uint8_t *counter)
{
    (*counter)++;
    if (*counter > 10) {
        /* To avoid an infinite loop on test case failure, eventually return success */
        return 0;
    }
    return -1;
}

int main(int argc, char **argv)
{
    BEGIN_TEST();

    /* Test S2N_IO_RETRY_EINTR */
    {
        const uint8_t n_times = 5;

        /* Retries on errno == EINTR */
        {
            uint8_t counter = 0;
            int result = 0;
            S2N_IO_RETRY_EINTR(result, s2n_test_mocked_interrupt(n_times, &counter));
            EXPECT_EQUAL(result, S2N_TEST_SUCCESS);
            EXPECT_EQUAL(counter, n_times);
        };

        /* Retries on real interrupt */
        {
            DEFER_CLEANUP(struct s2n_test_io_pair io_pair = { 0 }, s2n_io_pair_close);
            EXPECT_SUCCESS(s2n_io_pair_init(&io_pair));

            struct sigaction action = {
                .sa_handler = s2n_test_sig_handler,
            };
            sigaction(SIGUSR1, &action, NULL);

            fflush(stdout);
            pid_t pid = fork();
            if (pid == 0) {
                uint8_t counter = 0;
                int result = 0;
                S2N_IO_RETRY_EINTR(result,
                        s2n_test_real_interrupt(io_pair.client, n_times, &counter));
                EXPECT_EQUAL(result, S2N_TEST_SUCCESS);
                EXPECT_EQUAL(counter, n_times);
                exit(0);
            }

            /* Keep sending the signal until the process exits */
            int status = 0;
            while (waitpid(pid, &status, WNOHANG) == 0) {
                EXPECT_EQUAL(kill(pid, S2N_TEST_SIGNAL), 0);
            }
            EXPECT_EQUAL(status, EXIT_SUCCESS);
        };

        /* Handles IO methods that don't properly set errno */
        {
            /* Set errno to EINTR to try to trigger retry */
            errno = EINTR;

            uint8_t counter = 0;
            int result = 0;
            S2N_IO_RETRY_EINTR(result, s2n_fail_without_errno(&counter));
            EXPECT_EQUAL(result, -1);
            EXPECT_EQUAL(counter, 1);
            EXPECT_EQUAL(errno, 0);
        };
    };

    END_TEST();
}
