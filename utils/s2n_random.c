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

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <pthread.h>
#include <limits.h>
#include <fcntl.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>

#include "stuffer/s2n_stuffer.h"

#include "error/s2n_errno.h"

#include "tls/s2n_record.h"

#include "utils/s2n_safety.h"
#include "utils/s2n_random.h"

#define ENTROPY_SOURCE "/dev/urandom"

static int entropy_fd = -1;
static const RAND_METHOD *original_rand_method;

int s2n_get_random_data(uint8_t *data, uint32_t n)
{
    if (entropy_fd == -1) {
        S2N_ERROR(S2N_ERR_RANDOM_UNITIALIZED);
    }

    while (n) {
        int r = read(entropy_fd, data, n);
        if (r <= 0) {
            sleep(1);
            continue;
        }

        data += r;
        n -= r;
    }

    return 0;
}

int s2n_stuffer_write_random_data(struct s2n_stuffer *stuffer, uint32_t n)
{
    if (entropy_fd == -1) {
        S2N_ERROR(S2N_ERR_RANDOM_UNITIALIZED);
        return -1;
    }

    while (n) {
        int r = s2n_stuffer_recv_from_fd(stuffer, entropy_fd, n);
        if (r <= 0) {
            sleep(1);
            continue;
        }
        n -= r;
    }

    return 0;
}

int s2n_random(int max)
{
    unsigned int r;

    gt_check(max, 0);

    while(1) {
        GUARD(s2n_get_random_data((uint8_t *) &r, sizeof(r)));

        /* Imagine an int was one byte and UINT_MAX was 256. If the
         * caller asked for s2n_random(129, ...) we'd end up in
         * trouble. Each number in the range 0...127 would be twice
         * as likely as 128. That's because r == 0 % 129 -> 0, and
         * r == 129 % 129 -> 0, but only r == 128 returns 128, 
         * r == 257 is out of range.
         *
         * To de-bias the dice, we discard values of r that are higher
         * that the highest multiple of 'max' an int can support. If
         * max is a uint, then in the worst case we discard 50% - 1 r's. 
         * But since 'max' is an int and INT_MAX is <= UINT_MAX / 2, 
         * in the worst case we discard 25% - 1 r's. 
         */
        if (r < (UINT_MAX - (UINT_MAX % max))) {
            return r % max;
        }
    }

    return -1;
}

int openssl_compat_rand(unsigned char *buf, int num)
{
    int r = s2n_get_random_data(buf, num);
    if (r < 0) {
        return 0;
    }
    return 1;
}

void openssl_compat_seed(const void *buf, int num)
{

}

int openssl_compat_status()
{
    return 1;
}

void openssl_compat_cleanup()
{

}

void openssl_compat_add(const void *buf, int num, double entropy)
{

}

RAND_METHOD s2n_openssl_rand_method = {
    .seed = openssl_compat_seed,
    .bytes = openssl_compat_rand,
    .cleanup = openssl_compat_cleanup,
    .add = openssl_compat_add,
    .pseudorand = openssl_compat_rand,
    .status = openssl_compat_status
};

int s2n_init()
{
    entropy_fd = open(ENTROPY_SOURCE, O_RDONLY);
    if (entropy_fd == -1) {
        S2N_ERROR(S2N_ERR_OPEN_RANDOM);
    }

    original_rand_method = RAND_get_rand_method();

    /* Over-ride OpenSSL's PRNG. NOTE: there is a unit test to validate that this works */
    RAND_set_rand_method(&s2n_openssl_rand_method);

    /* Create the CBC masks */
    GUARD(s2n_cbc_masks_init());

    return 0;
}

int s2n_cleanup()
{
    if (entropy_fd == -1) {
        S2N_ERROR(S2N_ERR_NOT_INITIALIZED);
    }

    GUARD(close(entropy_fd));

    /* Restore OpenSSL's original random methods */
    RAND_set_rand_method(original_rand_method);

    return 0;
}
