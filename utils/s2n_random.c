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
        /* Clean up the old drbg first */
        GUARD(s2n_rand_cleanup_thread());
        /* Instantiate the new ones */
        GUARD(s2n_drbg_instantiate(&per_thread_public_drbg, &public, S2N_AES_128_CTR_NO_DF_PR));
        GUARD(s2n_drbg_instantiate(&per_thread_private_drbg, &private, S2N_AES_128_CTR_NO_DF_PR));
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

/*
 * Return a random number in the range [0, bound)
 */
int64_t s2n_public_random(int64_t bound)
{
    uint64_t r;

    gt_check(bound, 0);

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
         * that the highest multiple of 'bound' an int can support. If
         * bound is a uint, then in the worst case we discard 50% - 1 r's.
         * But since 'bound' is an int and INT_MAX is <= UINT_MAX / 2,
         * in the worst case we discard 25% - 1 r's.
         */
        if (r < (UINT64_MAX - (UINT64_MAX % bound))) {
            return r % bound;
        }
    }
}

#if S2N_LIBCRYPTO_SUPPORTS_CUSTOM_RAND

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
    S2N_ERROR_IF(zero_if_forked_ptr == MAP_FAILED, S2N_ERR_OPEN_RANDOM);

    S2N_ERROR_IF(minherit(zero_if_forked_ptr, sizeof(int), MAP_INHERIT_ZERO) == -1, S2N_ERR_OPEN_RANDOM);
#else

    S2N_ERROR_IF(pthread_atfork(NULL, NULL, s2n_on_fork) != 0, S2N_ERR_OPEN_RANDOM);
#endif

    GUARD(s2n_defend_if_forked());

#if S2N_LIBCRYPTO_SUPPORTS_CUSTOM_RAND
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
    S2N_ERROR_IF(e == NULL || ENGINE_init(e) != 1 || ENGINE_set_default(e, ENGINE_METHOD_RAND) != 1 || ENGINE_free(e) != 1, S2N_ERR_OPEN_RANDOM);
#endif

    return 0;
}

int s2n_rand_cleanup(void)
{
    S2N_ERROR_IF(entropy_fd == -1, S2N_ERR_NOT_INITIALIZED);

    GUARD(close(entropy_fd));
    entropy_fd = -1;

#if S2N_LIBCRYPTO_SUPPORTS_CUSTOM_RAND
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

int s2n_rand_cleanup_thread(void)
{
    GUARD(s2n_drbg_wipe(&per_thread_private_drbg));
    GUARD(s2n_drbg_wipe(&per_thread_public_drbg));

    return 0;
}

/*
 * This must only be used for unit tests. Any real use is dangerous and will be overwritten in s2n_defend_if_forked if
 * it is forked. This was added to support known answer tests that use OpenSSL and s2n_get_private_random_data directly.
 */
int s2n_set_private_drbg_for_test(struct s2n_drbg drbg)
{
    S2N_ERROR_IF(!s2n_in_unit_test(), S2N_ERR_NOT_IN_UNIT_TEST);
    GUARD(s2n_drbg_wipe(&per_thread_private_drbg));

    per_thread_private_drbg = drbg;
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

/*
 * volatile is important to prevent the compiler from
 * re-ordering or optimizing the use of RDRAND.
 */
int s2n_get_rdrand_data(struct s2n_blob *out)
{

#if defined(__x86_64__) || defined(__i386__)
    int space_remaining = 0;
    struct s2n_stuffer stuffer = {0};
    union {
        uint64_t u64;
#if defined(__i386__)
        struct {
            /* since we check first that we're on intel, we can safely assume little endian. */
            uint32_t u_low;
            uint32_t u_high;
        } i386_fields;
#endif /* defined(__i386__) */
        uint8_t u8[8];
    } output;

    GUARD(s2n_stuffer_init(&stuffer, out));
    while ((space_remaining = s2n_stuffer_space_remaining(&stuffer))) {
        unsigned char success = 0;
        output.u64 = 0;

        for (int tries = 0; tries < 10; tries++) {
#if defined(__i386__)
            /* execute the rdrand instruction, store the result in a general purpose register (it's assigned to
            * output.i386_fields.u_low). Check the carry bit, which will be set on success. Then clober the register and reset
            * the carry bit. Due to needing to support an ancient assembler we use the opcode syntax.
            * the %b1 is to force compilers to use c1 instead of ecx.
            * Here's a description of how the opcode is encoded:
            * 0x0fc7 (rdrand)
            * 0xf0 (store the result in eax).
            */
            unsigned char success_high = 0, success_low = 0;
            __asm__ __volatile__(".byte 0x0f, 0xc7, 0xf0;\n" "setc %b1;\n": "=a"(output.i386_fields.u_low), "=qm"(success_low)
                                 :
                                 :"cc");

            __asm__ __volatile__(".byte 0x0f, 0xc7, 0xf0;\n" "setc %b1;\n": "=a"(output.i386_fields.u_high), "=qm"(success_high)
                                 :
                                 :"cc");
            /* cppcheck-suppress knownConditionTrueFalse */
            success = success_high & success_low;
#else
            /* execute the rdrand instruction, store the result in a general purpose register (it's assigned to
            * output.u64). Check the carry bit, which will be set on success. Then clober the carry bit.
            * Due to needing to support an ancient assembler we use the opcode syntax.
            * the %b1 is to force compilers to use c1 instead of ecx.
            * Here's a description of how the opcode is encoded:
            * 0x48 (pick a 64-bit register it does more too, but that's all that matters there)
            * 0x0fc7 (rdrand)
            * 0xf0 (store the result in rax). */
            __asm__ __volatile__(".byte 0x48, 0x0f, 0xc7, 0xf0;\n" "setc %b1;\n": "=a"(output.u64), "=qm"(success)
            :
            :"cc");
#endif /* defined(__i386__) */

            if (success) {
                break;
            }
        }

        S2N_ERROR_IF(!success, S2N_ERR_RDRAND_FAILED);

        int data_to_fill = MIN(sizeof(output), space_remaining);

        GUARD(s2n_stuffer_write_bytes(&stuffer, output.u8, data_to_fill));
    }

    return 0;
#else
    S2N_ERROR(S2N_ERR_UNSUPPORTED_CPU);
#endif
}
