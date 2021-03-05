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
#include <stdlib.h>
#include <errno.h>
#include <time.h>

#include "s2n.h"

#if defined(S2N_CPUID_AVAILABLE)
#include <cpuid.h>
#endif

#include "stuffer/s2n_stuffer.h"

#include "crypto/s2n_drbg.h"

#include "error/s2n_errno.h"

#include "utils/s2n_result.h"
#include "utils/s2n_safety.h"
#include "utils/s2n_random.h"
#include "utils/s2n_mem.h"

#include <openssl/rand.h>

#define ENTROPY_SOURCE "/dev/urandom"

/* See https://en.wikipedia.org/wiki/CPUID */
#define RDRAND_ECX_FLAG     0x40000000

/* One second in nanoseconds */
#define ONE_S  INT64_C(1000000000)

/* Placeholder value for an uninitialized entropy file descriptor */
#define UNINITIALIZED_ENTROPY_FD -1

static int entropy_fd = UNINITIALIZED_ENTROPY_FD;

static __thread struct s2n_drbg per_thread_private_drbg = {0};
static __thread struct s2n_drbg per_thread_public_drbg = {0};

static void *zeroed_when_forked_page;
static int zero = 0;

static __thread void *zero_if_forked_ptr = &zero;
#define zero_if_forked (* (int *) zero_if_forked_ptr)

static int s2n_rand_init_impl(void);
static int s2n_rand_cleanup_impl(void);
static int s2n_rand_urandom_impl(void *ptr, uint32_t size);
static int s2n_rand_rdrand_impl(void *ptr, uint32_t size);

static s2n_rand_init_callback s2n_rand_init_cb = s2n_rand_init_impl;
static s2n_rand_cleanup_callback s2n_rand_cleanup_cb = s2n_rand_cleanup_impl;
static s2n_rand_seed_callback s2n_rand_seed_cb = s2n_rand_urandom_impl;
static s2n_rand_mix_callback s2n_rand_mix_cb = s2n_rand_urandom_impl;

bool s2n_cpu_supports_rdrand() {
#if defined(S2N_CPUID_AVAILABLE)
    uint32_t eax, ebx, ecx, edx;
    if (!__get_cpuid(1, &eax, &ebx, &ecx, &edx)) {
        return false;
    }

    if (ecx & RDRAND_ECX_FLAG) {
        return true;
    }
#endif
    return false;
}

int s2n_rand_set_callbacks(s2n_rand_init_callback rand_init_callback,
                             s2n_rand_cleanup_callback rand_cleanup_callback,
                             s2n_rand_seed_callback rand_seed_callback,
                             s2n_rand_mix_callback rand_mix_callback)
{
    s2n_rand_init_cb = rand_init_callback;
    s2n_rand_cleanup_cb = rand_cleanup_callback;
    s2n_rand_seed_cb = rand_seed_callback;
    s2n_rand_mix_cb = rand_mix_callback;

    return S2N_SUCCESS;
}

S2N_RESULT s2n_get_seed_entropy(struct s2n_blob *blob)
{
    RESULT_ENSURE_REF(blob);

    RESULT_GUARD_POSIX(s2n_rand_seed_cb(blob->data, blob->size));

    return S2N_RESULT_OK;
}

S2N_RESULT s2n_get_mix_entropy(struct s2n_blob *blob)
{
    RESULT_ENSURE_REF(blob);

    RESULT_GUARD_POSIX(s2n_rand_mix_cb(blob->data, blob->size));

    return S2N_RESULT_OK;
}

void s2n_on_fork(void)
{
    zero_if_forked = 0;
}

static inline S2N_RESULT s2n_defend_if_forked(void)
{
    uint8_t s2n_public_drbg[] = "s2n public drbg";
    uint8_t s2n_private_drbg[] = "s2n private drbg";
    struct s2n_blob public = {.data = s2n_public_drbg,.size = sizeof(s2n_public_drbg) };
    struct s2n_blob private = {.data = s2n_private_drbg,.size = sizeof(s2n_private_drbg) };

    if (zero_if_forked == 0) {
        /* Clean up the old drbg first */
        RESULT_GUARD(s2n_rand_cleanup_thread());
        /* Instantiate the new ones */
        RESULT_GUARD_POSIX(s2n_drbg_instantiate(&per_thread_public_drbg, &public, S2N_AES_128_CTR_NO_DF_PR));
        RESULT_GUARD_POSIX(s2n_drbg_instantiate(&per_thread_private_drbg, &private, S2N_AES_128_CTR_NO_DF_PR));
        zero_if_forked_ptr = zeroed_when_forked_page;
        zero_if_forked = 1;
    }

    return S2N_RESULT_OK;
}

S2N_RESULT s2n_get_public_random_data(struct s2n_blob *blob)
{
    RESULT_GUARD(s2n_defend_if_forked());

    uint32_t offset = 0;
    uint32_t remaining = blob->size;

    while(remaining) {
        struct s2n_blob slice = { 0 };

        RESULT_GUARD_POSIX(s2n_blob_slice(blob, &slice, offset, MIN(remaining, S2N_DRBG_GENERATE_LIMIT)));;

        RESULT_GUARD_POSIX(s2n_drbg_generate(&per_thread_public_drbg, &slice));

        remaining -= slice.size;
        offset += slice.size;
    }

    return S2N_RESULT_OK;
}

S2N_RESULT s2n_get_private_random_data(struct s2n_blob *blob)
{
    RESULT_GUARD(s2n_defend_if_forked());

    uint32_t offset = 0;
    uint32_t remaining = blob->size;

    while(remaining) {
        struct s2n_blob slice = { 0 };

        RESULT_GUARD_POSIX(s2n_blob_slice(blob, &slice, offset, MIN(remaining, S2N_DRBG_GENERATE_LIMIT)));;

        RESULT_GUARD_POSIX(s2n_drbg_generate(&per_thread_private_drbg, &slice));

        remaining -= slice.size;
        offset += slice.size;
    }

    return S2N_RESULT_OK;
}

S2N_RESULT s2n_get_public_random_bytes_used(uint64_t *bytes_used)
{
    RESULT_GUARD_POSIX(s2n_drbg_bytes_used(&per_thread_public_drbg, bytes_used));
    return S2N_RESULT_OK;
}

S2N_RESULT s2n_get_private_random_bytes_used(uint64_t *bytes_used)
{
    RESULT_GUARD_POSIX(s2n_drbg_bytes_used(&per_thread_private_drbg, bytes_used));
    return S2N_RESULT_OK;
}

static int s2n_rand_urandom_impl(void *ptr, uint32_t size)
{
    POSIX_ENSURE(entropy_fd != UNINITIALIZED_ENTROPY_FD, S2N_ERR_NOT_INITIALIZED);

    uint8_t *data = ptr;
    uint32_t n = size;
    struct timespec sleep_time = {.tv_sec = 0, .tv_nsec = 0 };
    long backoff = 1;

    while (n) {
        errno = 0;
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

    return S2N_SUCCESS;
}

/*
 * Return a random number in the range [0, bound)
 */
S2N_RESULT s2n_public_random(int64_t bound, uint64_t *output)
{
    uint64_t r;

    RESULT_ENSURE_GT(bound, 0);

    while (1) {
        struct s2n_blob blob = {.data = (void *)&r, sizeof(r) };
        RESULT_GUARD(s2n_get_public_random_data(&blob));

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
            *output = r % bound;
            return S2N_RESULT_OK;
        }
    }
}

#if S2N_LIBCRYPTO_SUPPORTS_CUSTOM_RAND

int s2n_openssl_compat_rand(unsigned char *buf, int num)
{
    struct s2n_blob out = {.data = buf,.size = num };

    if (s2n_result_is_error(s2n_get_private_random_data(&out))) {
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

static int s2n_rand_init_impl(void)
{
  OPEN:
    entropy_fd = open(ENTROPY_SOURCE, O_RDONLY);
    if (entropy_fd == S2N_FAILURE) {
        if (errno == EINTR) {
            goto OPEN;
        }
        POSIX_BAIL(S2N_ERR_OPEN_RANDOM);
    }

    if (s2n_cpu_supports_rdrand()) {
       s2n_rand_mix_cb = s2n_rand_rdrand_impl;
    }

    return S2N_SUCCESS;
}

S2N_RESULT s2n_rand_init(void)
{
    uint32_t pagesize;

    RESULT_GUARD_POSIX(s2n_rand_init_cb());

    pagesize = s2n_mem_get_page_size();

    /* We need a single-aligned page for our protected memory region */
    RESULT_ENSURE(posix_memalign(&zeroed_when_forked_page, pagesize, pagesize) == S2N_SUCCESS, S2N_ERR_OPEN_RANDOM);
    RESULT_ENSURE(zeroed_when_forked_page != NULL, S2N_ERR_OPEN_RANDOM);

    /* Initialized to zero to ensure that we seed our DRBGs */
    zero_if_forked = 0;

    /* INHERIT_ZERO and WIPEONFORK reset a page to all-zeroes when a fork occurs */
#if defined(MAP_INHERIT_ZERO)
    RESULT_ENSURE(minherit(zeroed_when_forked_page, pagesize, MAP_INHERIT_ZERO) != S2N_FAILURE, S2N_ERR_OPEN_RANDOM);
#endif

#if defined(MADV_WIPEONFORK)
    RESULT_ENSURE(madvise(zeroed_when_forked_page, pagesize, MADV_WIPEONFORK) == S2N_SUCCESS, S2N_ERR_OPEN_RANDOM);
#endif

    /* For defence in depth */
    RESULT_ENSURE(pthread_atfork(NULL, NULL, s2n_on_fork) == S2N_SUCCESS, S2N_ERR_OPEN_RANDOM);

    /* Seed everything */
    RESULT_GUARD(s2n_defend_if_forked());

#if S2N_LIBCRYPTO_SUPPORTS_CUSTOM_RAND
    /* Create an engine */
    ENGINE *e = ENGINE_new();

    RESULT_ENSURE(e != NULL, S2N_ERR_OPEN_RANDOM);
    RESULT_GUARD_OSSL(ENGINE_set_id(e, "s2n_rand"), S2N_ERR_OPEN_RANDOM);
    RESULT_GUARD_OSSL(ENGINE_set_name(e, "s2n entropy generator"), S2N_ERR_OPEN_RANDOM);
    RESULT_GUARD_OSSL(ENGINE_set_flags(e, ENGINE_FLAGS_NO_REGISTER_ALL), S2N_ERR_OPEN_RANDOM);
    RESULT_GUARD_OSSL(ENGINE_set_init_function(e, s2n_openssl_compat_init), S2N_ERR_OPEN_RANDOM);
    RESULT_GUARD_OSSL(ENGINE_set_RAND(e, &s2n_openssl_rand_method), S2N_ERR_OPEN_RANDOM);
    RESULT_GUARD_OSSL(ENGINE_add(e), S2N_ERR_OPEN_RANDOM);
    RESULT_GUARD_OSSL(ENGINE_free(e) , S2N_ERR_OPEN_RANDOM);

    /* Use that engine for rand() */
    e = ENGINE_by_id("s2n_rand");
    RESULT_ENSURE(e != NULL, S2N_ERR_OPEN_RANDOM);
    RESULT_GUARD_OSSL(ENGINE_init(e), S2N_ERR_OPEN_RANDOM);
    RESULT_GUARD_OSSL(ENGINE_set_default(e, ENGINE_METHOD_RAND), S2N_ERR_OPEN_RANDOM);
    RESULT_GUARD_OSSL(ENGINE_free(e), S2N_ERR_OPEN_RANDOM);
#endif

    return S2N_RESULT_OK;
}

static int s2n_rand_cleanup_impl(void)
{
    POSIX_ENSURE(entropy_fd != UNINITIALIZED_ENTROPY_FD, S2N_ERR_NOT_INITIALIZED);

    POSIX_GUARD(close(entropy_fd));
    entropy_fd = UNINITIALIZED_ENTROPY_FD;

    return S2N_SUCCESS;
}

S2N_RESULT s2n_rand_cleanup(void)
{
    RESULT_GUARD_POSIX(s2n_rand_cleanup_cb());

#if S2N_LIBCRYPTO_SUPPORTS_CUSTOM_RAND
    /* Cleanup our rand ENGINE in libcrypto */
    ENGINE *rand_engine = ENGINE_by_id("s2n_rand");
    if (rand_engine) {
        ENGINE_finish(rand_engine);
        ENGINE_free(rand_engine);
        ENGINE_cleanup();
    }
#endif

    s2n_rand_init_cb = s2n_rand_init_impl;
    s2n_rand_cleanup_cb = s2n_rand_cleanup_impl;
    s2n_rand_seed_cb = s2n_rand_urandom_impl;
    s2n_rand_mix_cb = s2n_rand_urandom_impl;

    return S2N_RESULT_OK;
}

S2N_RESULT s2n_rand_cleanup_thread(void)
{
    RESULT_GUARD_POSIX(s2n_drbg_wipe(&per_thread_private_drbg));
    RESULT_GUARD_POSIX(s2n_drbg_wipe(&per_thread_public_drbg));

    return S2N_RESULT_OK;
}

/*
 * This must only be used for unit tests. Any real use is dangerous and will be overwritten in s2n_defend_if_forked if
 * it is forked. This was added to support known answer tests that use OpenSSL and s2n_get_private_random_data directly.
 */
S2N_RESULT s2n_set_private_drbg_for_test(struct s2n_drbg drbg)
{
    RESULT_ENSURE(s2n_in_unit_test(), S2N_ERR_NOT_IN_UNIT_TEST);
    RESULT_GUARD_POSIX(s2n_drbg_wipe(&per_thread_private_drbg));

    per_thread_private_drbg = drbg;
    return S2N_RESULT_OK;
}

/*
 * volatile is important to prevent the compiler from
 * re-ordering or optimizing the use of RDRAND.
 */
static int s2n_rand_rdrand_impl(void *data, uint32_t size)
{
#if defined(__x86_64__) || defined(__i386__)
    struct s2n_blob out = { .data = data, .size = size };
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

    POSIX_GUARD(s2n_stuffer_init(&stuffer, &out));
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

            /* Treat either all 1 or all 0 bits in either the high or low order
             * bits as failure */
            if (output.i386_fields.u_low == 0 ||
                    output.i386_fields.u_low == UINT32_MAX ||
                    output.i386_fields.u_high == 0 ||
                    output.i386_fields.u_high == UINT32_MAX) {
                success = 0;
            }
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

            /* Some AMD CPUs will find that RDRAND "sticks" on all 1s but still reports success.
             * Some other very old CPUs use all 0s as an error condition while still reporting success.
             * If we encounter either of these suspicious values (a 1/2^63 chance) we'll treat them as
             * a failure and generate a new value.
             *
             * In the future we could add CPUID checks to detect processors with these known bugs,
             * however it does not appear worth it. The entropy loss is negligible and the
             * corresponding likelihood that a healthy CPU generates either of these values is also
             * negligible (1/2^63). Finally, adding processor specific logic would greatly
             * increase the complexity and would cause us to "miss" any unknown processors with
             * similar bugs. */
            if (output.u64 == UINT64_MAX ||
                output.u64 == 0) {
                success = 0;
            }

            if (success) {
                break;
            }
        }

        POSIX_ENSURE(success, S2N_ERR_RDRAND_FAILED);

        int data_to_fill = MIN(sizeof(output), space_remaining);

        POSIX_GUARD(s2n_stuffer_write_bytes(&stuffer, output.u8, data_to_fill));
    }

    return S2N_SUCCESS;
#else
    POSIX_BAIL(S2N_ERR_UNSUPPORTED_CPU);
#endif
}
