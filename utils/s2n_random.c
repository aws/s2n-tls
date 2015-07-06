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

#include <openssl/engine.h>

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

#include "crypto/s2n_drbg.h"

#include "error/s2n_errno.h"

#include "tls/s2n_record.h"

#include "utils/s2n_safety.h"
#include "utils/s2n_random.h"

#define ENTROPY_SOURCE "/dev/urandom"

static int entropy_fd = -1;

static __thread struct s2n_drbg per_thread_private_drbg = { { 0 } };
static __thread struct s2n_drbg per_thread_public_drbg = { { 0 } };

#if !defined(MAP_INHERIT_ZERO)
static __thread int zero_if_forked = 0;

void s2n_on_fork(void)
{
    zero_if_forked = 0;
}

#else

static __thread int *zero_if_forked_ptr;
#define zero_if_forked (*zero_if_forked_ptr)

#endif

static inline int s2n_check_fork(void)
{
    uint8_t s2n_public_drbg[] = "s2n public drbg";
    uint8_t s2n_private_drbg[] = "s2n private drbg";
    struct s2n_blob public = { .data = s2n_public_drbg, .size = sizeof(s2n_public_drbg) };
    struct s2n_blob private = { .data = s2n_private_drbg, .size = sizeof(s2n_private_drbg) };

    if (zero_if_forked == 0) {
        GUARD(s2n_drbg_instantiate(&per_thread_public_drbg, &public));
        GUARD(s2n_drbg_instantiate(&per_thread_private_drbg, &private));
        zero_if_forked = 1;
    }

    return 0;
}

int s2n_get_public_random_data(struct s2n_blob *blob)
{
    GUARD(s2n_check_fork());
    GUARD(s2n_drbg_generate(&per_thread_public_drbg, blob));

    return 0;
}

int s2n_get_private_random_data(struct s2n_blob *blob)
{
    GUARD(s2n_check_fork());
    GUARD(s2n_drbg_generate(&per_thread_private_drbg, blob));

    return 0;
}

int s2n_get_urandom_data(struct s2n_blob *blob)
{
    uint32_t n = blob->size;
    uint8_t *data = blob->data;

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

int s2n_public_random(int max)
{
    unsigned int r;

    gt_check(max, 0);

    while(1) {
        struct s2n_blob blob = { .data = (void *) &r, sizeof(r) };
        GUARD(s2n_get_public_random_data(&blob));

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

#ifndef OPENSSL_IS_BORINGSSL

int s2n_openssl_compat_rand(unsigned char *buf, int num)
{
    struct s2n_blob out = {.data = buf, .size = num};

    if(s2n_get_private_random_data(&out) < 0) {
        return 0;
    }
    return 1;
}

int s2n_openssl_compat_status(void)
{
    return 1;
}

int s2n_openssl_compat_init(ENGINE *unused)
{
    return 1;
}

RAND_METHOD s2n_openssl_rand_method = {
    .seed = NULL,
    .bytes = s2n_openssl_compat_rand,
    .cleanup = NULL,
    .add = NULL,
    .pseudorand = s2n_openssl_compat_rand,
    .status = s2n_openssl_compat_status
};
#endif

int s2n_init(void)
{
    entropy_fd = open(ENTROPY_SOURCE, O_RDONLY);
    if (entropy_fd == -1) {
        S2N_ERROR(S2N_ERR_OPEN_RANDOM);
    }

    /* Create the CBC masks */
    GUARD(s2n_cbc_masks_init());

#if defined(MAP_INHERIT_ZERO)
    if ((zero_if_forked_ptr = mmap(NULL, sizeof(int), PROT_READ|PROT_WRITE,
                                   MAP_ANON|MAP_PRIVATE, -1, 0)) == MAP_FAILED) {
        S2N_ERROR(S2N_ERR_OPEN_RANDOM);
    }

    if (minherit(zero_if_forked_ptr, sizeof(int), MAP_INHERIT_ZERO) == -1) {
        S2N_ERROR(S2N_ERR_OPEN_RANDOM);
    }
#else

    if (pthread_atfork(NULL, NULL, s2n_on_fork) != 0) {
        S2N_ERROR(S2N_ERR_OPEN_RANDOM);
    }
#endif

    GUARD(s2n_check_fork());

#ifndef OPENSSL_IS_BORINGSSL
    /* Create an engine */
    ENGINE *e = ENGINE_new();
    if (e == NULL ||
        ENGINE_set_id(e, "s2n") != 1 ||
        ENGINE_set_name(e, "s2n entropy generator") != 1 ||
        ENGINE_set_flags(e, ENGINE_FLAGS_NO_REGISTER_ALL) != 1 ||
        ENGINE_set_init_function(e, s2n_openssl_compat_init) != 1 ||
        ENGINE_set_RAND(e, &s2n_openssl_rand_method) != 1 ||
        ENGINE_add(e) != 1 ||
        ENGINE_free(e) != 1) {
        S2N_ERROR(S2N_ERR_OPEN_RANDOM);
    }

    /* Use that engine for rand() */
    e = ENGINE_by_id("s2n");
    if (e == NULL ||
        ENGINE_init(e) != 1 ||
        ENGINE_set_default(e, ENGINE_METHOD_RAND) != 1) {
        S2N_ERROR(S2N_ERR_OPEN_RANDOM);
    }
#endif

    return 0;
}

int s2n_cleanup(void)
{
    if (entropy_fd == -1) {
        S2N_ERROR(S2N_ERR_NOT_INITIALIZED);
    }

    GUARD(s2n_drbg_wipe(&per_thread_private_drbg));
    GUARD(s2n_drbg_wipe(&per_thread_public_drbg));
    GUARD(close(entropy_fd));

    return 0;
}
