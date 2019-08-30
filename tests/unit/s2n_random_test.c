/*
 * Copyright 2014 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

#include "s2n_test.h"

#include <sys/wait.h>
#include <pthread.h>
#include <s2n.h>

#include "utils/s2n_random.h"

static uint8_t thread_data[2][100];

void *thread_safety_tester(void *slot)
{
    intptr_t slotnum = (intptr_t) slot;
    struct s2n_blob blob = {.data = thread_data[slotnum], .size = 100 };

    s2n_get_public_random_data(&blob);

    s2n_rand_cleanup_thread();

    return NULL;
}

void process_safety_tester(int write_fd)
{
    uint8_t pad[100];

    struct s2n_blob blob = {.data = pad, .size = 100 };
    s2n_get_public_random_data(&blob);

    /* Write the data we got to our pipe */
    if (write(write_fd, pad, 100) != 100) {
        _exit(100);
    }

    /* Close the pipe and exit */
    close(write_fd);
    _exit(0);
}

int main(int argc, char **argv)
{
    uint8_t bits[8] = { 0x80, 0x40, 0x20, 0x10, 0x08, 0x04, 0x02, 0x01 };
    uint8_t bit_set_run[8];
    int p[2], status;
    pid_t pid;
    uint8_t data[5120];
    uint8_t child_data[100];
    struct s2n_blob blob = {.data = data };

    pthread_t threads[2];

    BEGIN_TEST();

    /* Get one byte of data, to make sure the pool is (almost) full */
    blob.size = 1;
    EXPECT_SUCCESS(s2n_get_public_random_data(&blob));

    /* Create two threads and have them each grab 100 bytes */
    EXPECT_SUCCESS(pthread_create(&threads[0], NULL, thread_safety_tester, (void *)0));
    EXPECT_SUCCESS(pthread_create(&threads[1], NULL, thread_safety_tester, (void *)1));

    /* Wait for those threads to finish */
    EXPECT_SUCCESS(pthread_join(threads[0], NULL));
    EXPECT_SUCCESS(pthread_join(threads[1], NULL));

    /* Confirm that their data differs from each other */
    EXPECT_NOT_EQUAL(memcmp(thread_data[0], thread_data[1], 100), 0);

    /* Confirm that their data differs from the parent thread */
    blob.size = 100;
    EXPECT_SUCCESS(s2n_get_public_random_data(&blob));
    EXPECT_NOT_EQUAL(memcmp(thread_data[0], data, 100), 0);
    EXPECT_NOT_EQUAL(memcmp(thread_data[1], data, 100), 0);

    /* Create a pipe */
    EXPECT_SUCCESS(pipe(p));

    /* Create a child process */
    pid = fork();
    if (pid == 0) {
        /* This is the child process, close the read end of the pipe */
        EXPECT_SUCCESS(close(p[0]));
        process_safety_tester(p[1]);
    }

    /* This is the parent process, close the write end of the pipe */
    EXPECT_SUCCESS(close(p[1]));

    /* Read the child's data from the pipe */
    EXPECT_EQUAL(read(p[0], child_data, 100), 100);

    /* Get 100 bytes here in the parent process */
    blob.size = 100;
    EXPECT_SUCCESS(s2n_get_public_random_data(&blob));

    /* Confirm they differ */
    EXPECT_NOT_EQUAL(memcmp(child_data, data, 100), 0);

    /* Clean up */
    EXPECT_EQUAL(waitpid(pid, &status, 0), pid);
    EXPECT_EQUAL(status, 0);
    EXPECT_SUCCESS(close(p[0]));

    /* Get two sets of data in the same process/thread, and confirm that they
     * differ
     */
    blob.data = child_data;
    EXPECT_SUCCESS(s2n_get_public_random_data(&blob));
    blob.data = data;
    EXPECT_SUCCESS(s2n_get_public_random_data(&blob));
    EXPECT_NOT_EQUAL(memcmp(child_data, data, 100), 0);

    /* Try to fetch a volume of randomly generated data, every size between 1 and 5120
     * bytes.
     */
    int trailing_zeros[8];

    memset(trailing_zeros, 0, sizeof(trailing_zeros));
    for (int i = 0; i < 5120; i++) {
        blob.size = i;
        EXPECT_SUCCESS(s2n_get_public_random_data(&blob));

        if (i >= 64) {
            /* Set the run counts to 0 */
            memset(bit_set_run, 0, 8);

            /* Apply 8 monobit tests to the data. Basically, we're
             * looking for successive runs where a given bit is set.
             * If a run exists with any particular bit 64 times in 
             * a row, then the data doesn't look randomly generated.
             */
            for (int j = 0; j < i; j++) {
                for (int k = 0; k < 8; k++) {
                    if (data[j] & bits[k]) {
                        bit_set_run[k]++;

                        if (j >= 64) {
                            EXPECT_TRUE(bit_set_run[k] < 64);
                        }
                    } else {
                        bit_set_run[k] = 0;
                    }
                }
            }
        }
        /* A common mistake in array filling leaves the last bytes zero
         * depending on the length.
         */
        int remainder = i % 8;
        int non_zero_found = 0;
        for (int t = i - remainder; t < i; t++) {
            non_zero_found |= data[t];
        }
        if (!non_zero_found) {
            trailing_zeros[remainder]++;
        }
    }
    for (int t = 1; t < 8; t++) {
        EXPECT_TRUE(trailing_zeros[t] < 5120 / 16);
    }

    memset(trailing_zeros, 0, sizeof(trailing_zeros));
    for (int i = 0; i < 5120; i++) {
        blob.size = i;
        EXPECT_SUCCESS(s2n_get_private_random_data(&blob));

        if (i >= 64) {
            /* Set the run counts to 0 */
            memset(bit_set_run, 0, 8);

            /* Apply 8 monobit tests to the data. Basically, we're
             * looking for successive runs where a given bit is set.
             * If a run exists with any particular bit 64 times in 
             * a row, then the data doesn't look randomly generated.
             */
            for (int j = 0; j < i; j++) {
                for (int k = 0; k < 8; k++) {
                    if (data[j] & bits[k]) {
                        bit_set_run[k]++;

                        if (j >= 64) {
                            EXPECT_TRUE(bit_set_run[k] < 64);
                        }
                    } else {
                        bit_set_run[k] = 0;
                    }
                }
            }
        }
        /* A common mistake in array filling leaves the last bytes zero
         * depending on the length.
         */
        int remainder = i % 8;
        int non_zero_found = 0;
        for (int t = i - remainder; t < i; t++) {
            non_zero_found |= data[t];
        }
        if (!non_zero_found) {
            trailing_zeros[remainder]++;
        }
    }
    for (int t = 1; t < 8; t++) {
        EXPECT_TRUE(trailing_zeros[t] < 5120 / 16);
    }

    memset(trailing_zeros, 0, sizeof(trailing_zeros));
    for (int i = 0; i < 5120; i++) {
        blob.size = i;
        EXPECT_SUCCESS(s2n_get_urandom_data(&blob));

        if (i >= 64) {
            /* Set the run counts to 0 */
            memset(bit_set_run, 0, 8);

            /* Apply 8 monobit tests to the data. Basically, we're
             * looking for successive runs where a given bit is set.
             * If a run exists with any particular bit 64 times in 
             * a row, then the data doesn't look randomly generated.
             */
            for (int j = 0; j < i; j++) {
                for (int k = 0; k < 8; k++) {
                    if (data[j] & bits[k]) {
                        bit_set_run[k]++;

                        if (j >= 64) {
                            EXPECT_TRUE(bit_set_run[k] < 64);
                        }
                    } else {
                        bit_set_run[k] = 0;
                    }
                }
            }
        }
        /* A common mistake in array filling leaves the last bytes zero
         * depending on the length.
         */
        int remainder = i % 8;
        int non_zero_found = 0;
        for (int t = i - remainder; t < i; t++) {
            non_zero_found |= data[t];
        }
        if (!non_zero_found) {
            trailing_zeros[remainder]++;
        }
    }
    for (int t = 1; t < 8; t++) {
        EXPECT_TRUE(trailing_zeros[t] < 5120 / 16);
    }

    if (s2n_cpu_supports_rdrand()) {
        memset(trailing_zeros, 0, sizeof(trailing_zeros));
        for (int i = 0; i < 5120; i++) {
            blob.size = i;
            EXPECT_SUCCESS(s2n_get_urandom_data(&blob));

            if (i >= 64) {
                /* Set the run counts to 0 */
                memset(bit_set_run, 0, 8);

                /* Apply 8 monobit tests to the data. Basically, we're
                 * looking for successive runs where a given bit is set.
                 * If a run exists with any particular bit 64 times in 
                 * a row, then the data doesn't look randomly generated.
                 */
                for (int j = 0; j < i; j++) {
                    for (int k = 0; k < 8; k++) {
                        if (data[j] & bits[k]) {
                            bit_set_run[k]++;

                            if (j >= 64) {
                                EXPECT_TRUE(bit_set_run[k] < 64);
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
            int remainder = i % 8;
            int non_zero_found = 0;
            for (int t = i - remainder; t < i; t++) {
              non_zero_found |= data[t];
            }
            if (!non_zero_found) {
              trailing_zeros[remainder]++;
            }
        }
        for (int t = 1; t < 8; t++) {
          EXPECT_TRUE(trailing_zeros[t] < 5120 / 16);
        }
    }

    END_TEST();
}
