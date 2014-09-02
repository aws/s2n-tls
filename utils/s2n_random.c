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
#include <fcntl.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>

#include "stuffer/s2n_stuffer.h"

#include "utils/s2n_safety.h"
#include "utils/s2n_random.h"

#define ENTROPY_SOURCE "/dev/urandom"

static int entropy_fd = -1;
static const RAND_METHOD *original_rand_method;

int s2n_get_random_data(uint8_t *data, uint32_t n, const char **err)
{
    if (entropy_fd == -1) {
        *err = "s2n_get_random_data() called before s2n_init()";
        return -1;
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

int s2n_stuffer_write_random_data(struct s2n_stuffer *stuffer, uint32_t n, const char **err)
{
    if (entropy_fd == -1) {
        *err = "s2n_get_random_data() called before s2n_init()";
        return -1;
    }

    while (n) {
        int r = s2n_stuffer_recv_from_fd(stuffer, entropy_fd, n, err);
        if (r <= 0) {
            sleep(1);
            continue;
        }
        n -= r;
    }

    return 0;
}

int openssl_compat_rand(unsigned char *buf, int num)
{
    const char *err;
    int r = s2n_get_random_data(buf, num, &err);
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

int s2n_init(const char **err)
{
    entropy_fd = open(ENTROPY_SOURCE, O_RDONLY);
    if (entropy_fd == -1) {
        *err = "Could not open entropy source";
        return -1;
    }

    original_rand_method = RAND_get_rand_method();

    /* Over-ride OpenSSL's PRNG. NOTE: there is a unit test to validate that this works */
    RAND_set_rand_method(&s2n_openssl_rand_method);

    return 0;
}

int s2n_cleanup(const char **err)
{
    if (entropy_fd == -1) {
        *err = "s2n was not initialized";
        return -1;
    }

    GUARD(close(entropy_fd));

    /* Restore OpenSSL's original random methods */
    RAND_set_rand_method(original_rand_method);

    return 0;
}
