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
#include <sys/param.h>
#include <unistd.h>
#include <pthread.h>
#include <limits.h>
#include <fcntl.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <time.h>

#include "utils/s2n_compiler.h"

/* clang can define gcc version to be < 4.3, but cpuid.h exists for most releases */
#if ((defined(__x86_64__) || defined(__i386__)) && (defined(__clang__) || S2N_GCC_VERSION_AT_LEAST(4,3,0)))
#include <cpuid.h>
#endif

#include "stuffer/s2n_stuffer.h"

#include "crypto/s2n_drbg.h"

#include "error/s2n_errno.h"

#include "utils/s2n_safety.h"
#include "utils/s2n_random.h"
#include "utils/s2n_mem.h"

#include <openssl/rand.h>

#define ENTROPY_SOURCE "/dev/urandom"

/* See https://en.wikipedia.org/wiki/CPUID */
#define RDRAND_ECX_FLAG     0x40000000

/* One second in nanoseconds */
#define ONE_S  INT64_C(1000000000)

static int entropy_fd = -1;

static __thread struct s2n_drbg per_thread_private_drbg = {0};
static __thread struct s2n_drbg per_thread_public_drbg = {0};

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

static inline int s2n_defend_if_forked(void)
{
    uint8_t s2n_public_drbg[] = "s2n public drbg";
    uint8_t s2n_private_drbg[] = "s2n private drbg";
    struct s2n_blob public = {.data = s2n_public_drbg,.size = sizeof(s2n_public_drbg) };
    struct s2n_blob private = {.data = s2n_private_drbg,.size = sizeof(s2n_private_drbg) };

    if (zero_if_forked == 0) {
        GUARD(s2n_drbg_instantiate(&per_thread_public_drbg, &public));
        GUARD(s2n_drbg_instantiate(&per_thread_private_drbg, &private));
        zero_if_forked = 1;
    }

    return 0;
}

int s2n_get_public_random_data(struct s2n_blob *blob)
{
    GUARD(s2n_defend_if_forked());
    GUARD(s2n_drbg_generate(&per_thread_public_drbg, blob));

    return 0;
}

int s2n_get_private_random_data(struct s2n_blob *blob)
{
    GUARD(s2n_defend_if_forked());
    GUARD(s2n_drbg_generate(&per_thread_private_drbg, blob));

    return 0;
}

int s2n_get_public_random_bytes_used(void)
{
    return s2n_drbg_bytes_used(&per_thread_public_drbg);
}

int s2n_get_private_random_bytes_used(void)
{
    return s2n_drbg_bytes_used(&per_thread_private_drbg);
}

int s2n_get_urandom_data(struct s2n_blob *blob)
{
    uint32_t n = blob->size;
    uint8_t *data = blob->data;
    struct timespec sleep_time = {.tv_sec = 0, .tv_nsec = 0 };
    long backoff = 1;

    while (n) {
        int r = read(entropy_fd, data, n);
        if (r <= 0) {
            /*
             * A non-blocking read() on /dev/urandom should "never" fail,
             * except for EINTR. If it does, briefly pause and use
             * exponential backoff to avoid creating a tight spinning loop.
             *
             * iteration          delay
             * ---------    -----------------
             *    1         10          nsec
             *    2         100         nsec
             *    3         1,000       nsec
             *    4         10,000      nsec
             *    5         100,000     nsec
             *    6         1,000,000   nsec
             *    7         10,000,000  nsec
             *    8         99,999,999  nsec
             *    9         99,999,999  nsec
             *    ...
             */
            if (errno != EINTR) {
                backoff = MIN(backoff * 10, ONE_S - 1);
                sleep_time.tv_nsec = backoff;
                do {
                    r = nanosleep(&sleep_time, &sleep_time);
                }
                while (r != 0);
            }

            continue;
        }

        data += r;
        n -= r;
    }

    return 0;
}

int64_t s2n_public_random(int64_t max)
{
    uint64_t r;

    gt_check(max, 0);

    while (1) {
        struct s2n_blob blob = {.data = (void *)&r, sizeof(r) };
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
        if (r < (UINT64_MAX - (UINT64_MAX % max))) {
            return r % max;
        }
    }
}

#if !defined(OPENSSL_IS_BORINGSSL) && !defined(OPENSSL_FIPS) && !defined(LIBRESSL_VERSION_NUMBER)

int s2n_openssl_compat_rand(unsigned char *buf, int num)
{
    struct s2n_blob out = {.data = buf,.size = num };

    if (s2n_get_private_random_data(&out) < 0) {
        return 0;
    }
    return 1;
}

int s2n_openssl_compat_status(void)
{
    return 1;
}

int s2n_openssl_compat_init(ENGINE * unused)
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

int s2n_rand_init(void)
{
  OPEN:
    entropy_fd = open(ENTROPY_SOURCE, O_RDONLY);
    if (entropy_fd == -1) {
        if (errno == EINTR) {
            goto OPEN;
        }
        S2N_ERROR(S2N_ERR_OPEN_RANDOM);
    }
#if defined(MAP_INHERIT_ZERO)
    zero_if_forked_ptr = mmap(NULL, sizeof(int), PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);
    if (zero_if_forked_ptr == MAP_FAILED) {
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

    GUARD(s2n_defend_if_forked());

#if !defined(OPENSSL_IS_BORINGSSL) && !defined(OPENSSL_FIPS) && !defined(LIBRESSL_VERSION_NUMBER)
    /* Create an engine */
    ENGINE *e = ENGINE_new();
    if (e == NULL ||
        ENGINE_set_id(e, "s2n_rand") != 1 ||
        ENGINE_set_name(e, "s2n entropy generator") != 1 ||
        ENGINE_set_flags(e, ENGINE_FLAGS_NO_REGISTER_ALL) != 1 ||
        ENGINE_set_init_function(e, s2n_openssl_compat_init) != 1 || ENGINE_set_RAND(e, &s2n_openssl_rand_method) != 1 || ENGINE_add(e) != 1 || ENGINE_free(e) != 1) {
        S2N_ERROR(S2N_ERR_OPEN_RANDOM);
    }

    /* Use that engine for rand() */
    e = ENGINE_by_id("s2n_rand");
    if (e == NULL || ENGINE_init(e) != 1 || ENGINE_set_default(e, ENGINE_METHOD_RAND) != 1 || ENGINE_free(e) != 1) {
        S2N_ERROR(S2N_ERR_OPEN_RANDOM);
    }
#endif

    return 0;
}

int s2n_rand_cleanup(void)
{
    if (entropy_fd == -1) {
        S2N_ERROR(S2N_ERR_NOT_INITIALIZED);
    }

    GUARD(s2n_drbg_wipe(&per_thread_private_drbg));
    GUARD(s2n_drbg_wipe(&per_thread_public_drbg));
    GUARD(close(entropy_fd));
    entropy_fd = -1;

#if !defined(OPENSSL_IS_BORINGSSL) && !defined(OPENSSL_FIPS) && !defined(LIBRESSL_VERSION_NUMBER)
    /* Cleanup our rand ENGINE in libcrypto */
    ENGINE *rand_engine = ENGINE_by_id("s2n_rand");
    if (rand_engine) {
        ENGINE_finish(rand_engine);
        ENGINE_free(rand_engine);
        ENGINE_cleanup();
    }
#endif

    return 0;
}

int s2n_cpu_supports_rdrand()
{
#if ((defined(__x86_64__) || defined(__i386__)) && (defined(__clang__) || S2N_GCC_VERSION_AT_LEAST(4,3,0)))
    uint32_t eax, ebx, ecx, edx;
    if (!__get_cpuid(1, &eax, &ebx, &ecx, &edx)) {
        return 0;
    }

    if (ecx & RDRAND_ECX_FLAG) {
        return 1;
    }
#endif
    return 0;
}

/* Due to the need to support some older assemblers,
 * we cannot use either the compiler intrinsics or
 * the RDRAND assembly mnemonic. For this reason,
 * we're using the opcode directly (0F C7/6). This
 * stores the result in eax.
 *
 * volatile is important to prevent the compiler from
 * re-ordering or optimizing the use of RDRAND.
 */
int s2n_get_rdrand_data(struct s2n_blob *out)
{

#if defined(__x86_64__) || defined(__i386__)
    int space_remaining = 0;
    struct s2n_stuffer stuffer;
    union {
        uint64_t u64;
        uint8_t u8[8];
    } output;

    GUARD(s2n_stuffer_init(&stuffer, out));

    while ((space_remaining = s2n_stuffer_space_remaining(&stuffer))) {
        int success = 0;

        for (int tries = 0; tries < 10; tries++) {
            __asm__ __volatile__(".byte 0x48;\n" ".byte 0x0f;\n" ".byte 0xc7;\n" ".byte 0xf0;\n" "adcl $0x00, %%ebx;\n":"=b"(success), "=a"(output.u64)
                                 :"b"(0)
                                 :"cc");

            if (success) {
                break;
            }
        }

        if (!success) {
            return -1;
        }

        int data_to_fill = MIN(sizeof(output), space_remaining);

        GUARD(s2n_stuffer_write_bytes(&stuffer, output.u8, data_to_fill));
    }

    return 0;
#else
    return -1;
#endif
}
