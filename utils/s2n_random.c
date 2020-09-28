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

static inline S2N_RESULT s2n_defend_if_forked(void)
{
    uint8_t s2n_public_drbg[] = "s2n public drbg";
    uint8_t s2n_private_drbg[] = "s2n private drbg";
    struct s2n_blob public = {.data = s2n_public_drbg,.size = sizeof(s2n_public_drbg) };
    struct s2n_blob private = {.data = s2n_private_drbg,.size = sizeof(s2n_private_drbg) };

    if (zero_if_forked == 0) {
        /* Clean up the old drbg first */
        GUARD_RESULT(s2n_rand_cleanup_thread());
        /* Instantiate the new ones */
        GUARD_AS_RESULT(s2n_drbg_instantiate(&per_thread_public_drbg, &public, S2N_AES_128_CTR_NO_DF_PR));
        GUARD_AS_RESULT(s2n_drbg_instantiate(&per_thread_private_drbg, &private, S2N_AES_128_CTR_NO_DF_PR));
        zero_if_forked = 1;
    }

    return S2N_RESULT_OK;
}

S2N_RESULT s2n_get_public_random_data(struct s2n_blob *blob)
{
    GUARD_RESULT(s2n_defend_if_forked());
    GUARD_AS_RESULT(s2n_drbg_generate(&per_thread_public_drbg, blob));

    return S2N_RESULT_OK;
}

S2N_RESULT s2n_get_private_random_data(struct s2n_blob *blob)
{
    GUARD_RESULT(s2n_defend_if_forked());
    GUARD_AS_RESULT(s2n_drbg_generate(&per_thread_private_drbg, blob));

    return S2N_RESULT_OK;
}

S2N_RESULT s2n_get_public_random_bytes_used(uint64_t *bytes_used)
{
    GUARD_AS_RESULT(s2n_drbg_bytes_used(&per_thread_public_drbg, bytes_used));
    return S2N_RESULT_OK;
}

S2N_RESULT s2n_get_private_random_bytes_used(uint64_t *bytes_used)
{
    GUARD_AS_RESULT(s2n_drbg_bytes_used(&per_thread_private_drbg, bytes_used));
    return S2N_RESULT_OK;
}

S2N_RESULT s2n_get_urandom_data(struct s2n_blob *blob)
{
    ENSURE(entropy_fd != UNINITIALIZED_ENTROPY_FD, S2N_ERR_NOT_INITIALIZED);

    uint32_t n = blob->size;
    uint8_t *data = blob->data;
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

    return S2N_RESULT_OK;
}

/*
 * Return a random number in the range [0, bound)
 */
S2N_RESULT s2n_public_random(int64_t bound, uint64_t *output)
{
    uint64_t x;

    ENSURE_GT(bound, 0);

    /*
     * This function implements Lemire's algorithm. You can read Lemire's blog post
     * and paper at:
     *
     * https://lemire.me/blog/2019/06/06/nearly-divisionless-random-integer-generation-on-various-systems/
     * https://arxiv.org/pdf/1805.10941.pdf
     *
     * But this massive comment is going to serve as a more concise explanation.
     *
     * Suppose we had uint3_t that is just 3 bits wide. That can represent the numbers
     * 0, 1, 2, 3, 4, 5, 6, 7. And we also have a function that can return a random
     * 3-bit number. uint3_t x = random3();
     *
     * Now let's say that we want to use that to generate a number in the set 0, 1, 2.
     * A naive way to to this is to simply use x % 3. % is the modulus or remainder
     * operator and it returns the remainder left over from x/3. The remainder will
     * always be smaller than 3 (obviously).
     *
     * If we lay the possibilities out on a number line, we can quickly see a problem:
     *
     *  x =         0  1  2  3  4  5  6  7
     *              +--+--+--+--+--+--+--+
     *  x % 3 =     0  1  2  0  1  2  0  1
     *
     * The results are unfair. There are 3 ways to get 0 or 1, but only 2 ways get
     * 2, so it won't be chosen as often. That's no good if we want a fair
     * probability.
     *
     * The usual fix for this is to do rejection sampling and to reject any value of
     * x higher than or equal to (rand_max - (rand_max % 3)). Or in code:
     *
     *  uint3_t ceiling = (UINT3_MAX - (UINT3_MAX % s);
     *  while(1) {
     *      uint3_t x = random3();
     *      if (x < ceiling)
     *          return r % s;
     *      }
     *  }
     *
     * On our number line this can be visualzed as:
     *
     *  x =         0  1  2  3  4  5  6  7
     *              +--+--+--+--+--+--+--+
     *              \_____/  \_____/
     *  x % 3 =     0  1  2  0  1  2
     *
     * if x comes up 6 or 7, we try again. That produces UINT3_MAX / s
     * "ranges" of legitimate values. In this case two 0s, two 1s, two 2s.
     *
     * With our code, we checked if x was between 0 and 5, because that's
     * easiest, but any contiguous window of 6 numbers would have done.
     * For example:
     *
     *  x =         0  1  2  3  4  5  6  7
     *              +--+--+--+--+--+--+--+
     *                 \_____/  \_____/
     *  x % 3 =        1  2  0  1  2  0
     *
     *  x =         0  1  2  3  4  5  6  7
     *              +--+--+--+--+--+--+--+
     *                    \_____/  \_____/
     *  x % 3 =           2  0  1  2  0  1
     *
     * There's a general principle at play here. Any contiguous range of
     * (n * s) numbers will contain exactly n values where x % s is 0, n values
     * where x % s is 1, and so on, up to n values where x % s is (s - 1).
     * This is important later, so really convince yourself of this.
     *
     * This algorithm works correctly but is expensive. There's at least two
     * % operations per call and maybe more, and those operations are among the
     * slowest a CPU can be asked to perform.
     *
     * To avoid this, we use Lemire's algorithm which cleverly replaces these
     * modulus operations with bit-shifts. Here's how it works.
     *
     * First, we generate a random value as before:
     *
     *  uint3_t x = random3();
     *
     * which can be visualized on a number line:
     *
     *  x =        0  1  2  3  4  5  6  7
     *             +--+--+--+--+--+--+--+
     *
     * We then multiply x by s. Recall that s is the size of the range we want,
     * i.e. to pick a number in the set 0, 1, 2 then s is 3.
     *
     *  uint6_t m = x * s;
     *
     * Note that m is twice the bit-width of x. It's a 6-bit int, enough to represent
     * the numbers 0-63. Since in our case s is 3, let's expand out all of the
     * possibilities for m with another number line.
     *
     *  x =        0  1  2  3  4  5  6  7
     *             +--+--+--+--+--+--+--+
     *             .  .  .  .  ..  .. .. .......
     *             .  .   .  ..  ... ..  ...    .......
     *             .   .   .    ...  ....     .... ..   .......
     *             .     .   .     ...   .....    ....  ....    .......
     *             .      .    . .    ...     .....   .....  ....      ......
     *             .      .        .     ....      ....    .....   .....     .....
     *  m =        .        3        6        9        12       15       18       21
     *             +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
     *
     * Our line stops at 21 because with s = 3, that's our maximum value for m. If
     * s was 6 (as when simulating a dice) it would go to 42. You get the idea.
     *
     * Now at any time we can "collapse" these numbers back to a set between 0-2 by
     * by dividing by 8. That's the same as "m >> 3" which is faster than actually
     * dividing.
     *
     *  m      =   0        3        6        9        12       15       18       21
     *             +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
     *  m >> 3 =   0        0        0        1        1        1        2        2
     *             \___________________/   \____________________/  \___________________/
     *
     * Note that the operand 3 here comes from from dividing a 6-bit number to a
     * 3-bit number, and not because s was 3. We'd still use 3, no matter what value
     * s originally had. For example if s was 5, then the m number line would look
     * like this:
     *
     *  m      =   0         5         10        15        20        25        30        35
     *             +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     *  m >> 3 =   0         0         1         1         2         3         3         4
     *             \_____________/ \_____________/ \_____________/ \_____________/ \_____________/
     *
     * Either way, m >> 3 is clearly unfair. So how do we fix it? We already have
     * the answer. Recall that any contiguous range of size (n * s) will contain
     * exactly n multiples of 0, 1, ... s - 1. Below each m >> 3 above in the
     * ascii art diagrams are boat-shaped ranges of size 8. Every value in the
     * first range is 0, it's 1 in the second, and so on.
     *
     * What we want to do is to select a sub-range of size (n * s) inside each of
     * of these ranges of size 8. We're going to do that by rejecting the first
     * (8 % s) values in each range from elligibility.
     *
     * Because each boat-shaped range is size 8, we can assign every value a position
     * 'l' in that range by virtue of:
     *
     *  uint3_t l = m % 8;
     *
     * again with the number line:
     *
     *  m      =   0        3        6        9        12       15       18       21
     *             +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
     *  m >> 3 =   0        0        0        1        1        1        2        2
     *  l      =   0  1  2  3  4  5  6  7  0  1  2  3  4  5  6  7  0  1  2  3  4  5  6  7
     *             \___________________/   \____________________/  \___________________/
     *
     * Our goal will be to reject values of m where l is less than 8 % s. Since s is 3,
     * that makes 8 % s is 2 and so we'll reject the any values in the first two 'slots'
     * of a range. That will leave us with a contiguous sub-range of size 6. Before we
     * get there though, another trick. We can speed up m % 8 by using bitwise math.
     * It's the same as:
     *
     *  uint3_t l = (uint3_t) m;
     *
     * Recall that m is a 6-bit int, so this operation truncates the value of m
     * to the value of its 3 least significant bits. Some examples in binary:
     *
     *  m = 0b101010  l = 0b010
     *  m = 0b010101  l = 0b101
     *  m = 0b001001  l = 0b001
     *  m = 0b111111  l = 0b111
     *
     * Why is this the same as:
     *
     *  uint3_t l = m % 8;
     *
     * ? It's because of how binary works, any values in the left-most 3-bits
     * represent a multiple of 8 (e.g. 8, 16, 32), and so any values in the
     * right-most bits are purely the remainder of m / 8.
     *
     * So now we can rewrite our algorithm as:
     *
     *  while(1) {
     *      uint3_t x = random3();
     *      uint6_t m = x * s;
     *      uint3_t l = (uint3_t) m;
     *      if (l < (8 % s))
     *          return m >> 3;
     *      }
     *  }
     *
     * This is ok, but we can do better. The first thing to notice is that
     * (8 % s) is always smaller than s, so we can avoid calculating it, at least
     * sometimes, by doing this:
     *
     *  uint3_t x = random3();
     *  uint6_t m = x * s;
     *  uint3_t l = (uint3_t) m;
     *  if ( l < s ) {
     *      uint3_t floor = 8 % s;
     *      while (l < floor) {
     *          uint3_t x = random3();
     *          uint6_t m = x * s;
     *          uint3_t l = (uint3_t) m;
     *      }
     *  }
     *  return m >> 3;
     *
     * again, because s is always bigger than the floor, if we picked a value
     * where l is greater than s, we can just go with it. No need to figure
     * out what the floor is exactly and we can avoid one of those expensive
     * division/modulus operations.
     *
     * But we need to do just a little more. Focus on this line of code:
     *
     *  uint3_t floor = 8 % s;
     *
     * The value 8 doesn't actually fit in a uint3, so this line mixes types.
     * To avoid this and to run faster, we're going to rewrite it as:
     *
     *  uint3_t floor = -s % s;
     *
     * How does -s % s == 8 % s (when using a 3-bit uint)? Let's break it down.
     * firstly, negation of an unsigned int in C is defined as taking the two's
     * complement. That means flipping all of the bits and adding one to the
     * result. Here's a table with all possible values of s, the bitwise not
     * of s (that means all of the bits are flipped, and is notated as ~s),
     * and the two's complement, -s. For a three-bit system.
     *
     *      s     |    ~s     |    -s
     *  0b000 = 0 | 0b111 = 7 | 0b000 = 0
     *  0b001 = 1 | 0b110 = 6 | 0b111 = 7
     *  0b010 = 2 | 0b101 = 5 | 0b110 = 6
     *  0b011 = 3 | 0b100 = 4 | 0b101 = 5
     *  0b100 = 4 | 0b011 = 3 | 0b100 = 4
     *  0b101 = 5 | 0b010 = 2 | 0b011 = 3
     *  0b110 = 6 | 0b001 = 1 | 0b010 = 2
     *  0b111 = 7 | 0b000 = 0 | 0b001 = 1
     *
     * From this, it's pretty easy to see that -s is the same as (8 - s).
     * Now remember what 8 % s is all about, it's about finding the remainder
     * from 8 / s. As long as s is no bigger than 8, subtracting exactly one
     * s from 8 can never change the remainder. So 8 % s is the same as
     * -s % s , when using uint3's.
     *
     * That leaves us with the final form of Lemire's algorithm:
     *
     *  uint3_t x = random3();
     *  uint6_t m = x * s;
     *  uint3_t l = (uint3_t) m;
     *  if ( l < s ) {
     *      uint3_t floor = -s % s;
     *      while (l < floor) {
     *          uint3_t x = random3();
     *          uint6_t m = x * s;
     *          uint3_t l = (uint3_t) m;
     *      }
     *  }
     *  return m >> 3;
     *
     * A NOTE ON SIDE-CHANNELS: Lemire's algorithm is fast, it cuts down on the
     * number of divisions, but it also has a timing side-channel that reveals
     * details about the numbers chosen.
     *
     * Suppose we wanted to simulate a dice with our dummy 3-bit / 6-bit
     * architecture. Here's how the number-line would look:
     *
     *  m      =   0           6           12          18          24          30          36          42
     *             +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     *  m >> 3 =   0           0           1           2           3           3           4           5
     *  l      =   0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
     *             \_____________/ \_____________/ \_____________/ \_____________/ \_____________/ \_____________/
     *
     * An attacker measuring the time that the algorithm takes can infer
     * information:
     *
     * 1/ The algorthim ran super fast. l was not smaller than s. This means the
     *    value is either 0 or 3.
     *
     * 2/ The algorithm ran intermediately fast. l was smaller than s but was
     *    not smaller than floor. This means the value is either 1, 2, 4, or 5.
     *
     * 3/ The algorithm ran slowly. Similar extrapolations as 1 and 2 can then
     *    be performed recursively to determine post-rejection values.
     *
     * Note that this side-channel isn't a result of rejection sampling; the very
     * first "simple" algorithm with rejection sampling does not have a side-channel
     * because rejection reveals nothing about the final value.
     *
     * Now, does it matter? Probably not. In the real world, side-channels like this
     * take repeated measurements to detect. But by definition each run of a random
     * function is going to produce a randomly-generated result. This will confound
     * the attack.
     *
     * But if you're worried about an attacker who can precisely measure a single
     * invokation of this algorithm, or some kind of already-broken system where
     * the randomN() function is deterministic, then maybe avoid this method.
     *
     * In s2n we use this function only in public contexts, it's in the name, so
     * we don't need to worry about this side-channel.
     */

    /* uint64_t x = random64() */
    struct s2n_blob x_blob = {.data = (void *)&x, sizeof(x) };
    GUARD_RESULT(s2n_get_public_random_data(&x_blob));

    __uint128_t m = ( __uint128_t ) x * ( __uint128_t ) bound;
    uint64_t l = ( uint64_t ) m;
    const uint64_t s = ( uint64_t ) bound;
    if (l < s) {
        /* cppcheck-suppress oppositeExpression */
        const uint64_t t = -s % s;
        while (l < t) {
            GUARD_RESULT(s2n_get_public_random_data(&x_blob));
            m = ( __uint128_t ) x * ( __uint128_t ) bound;
            l = ( uint64_t ) m;
        }
    }

    *output =  m >> 64;

    return S2N_RESULT_OK;
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

S2N_RESULT s2n_rand_init(void)
{
  OPEN:
    entropy_fd = open(ENTROPY_SOURCE, O_RDONLY);
    if (entropy_fd == S2N_FAILURE) {
        if (errno == EINTR) {
            goto OPEN;
        }
        BAIL(S2N_ERR_OPEN_RANDOM);
    }
#if defined(MAP_INHERIT_ZERO)
    zero_if_forked_ptr = mmap(NULL, sizeof(int), PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);
    ENSURE(zero_if_forked_ptr != MAP_FAILED, S2N_ERR_OPEN_RANDOM);

    ENSURE(minherit(zero_if_forked_ptr, sizeof(int), MAP_INHERIT_ZERO) != S2N_FAILURE, S2N_ERR_OPEN_RANDOM);
#else

    ENSURE(pthread_atfork(NULL, NULL, s2n_on_fork) == S2N_SUCCESS, S2N_ERR_OPEN_RANDOM);
#endif

    GUARD_RESULT(s2n_defend_if_forked());

#if S2N_LIBCRYPTO_SUPPORTS_CUSTOM_RAND
    /* Create an engine */
    ENGINE *e = ENGINE_new();

    ENSURE(e != NULL, S2N_ERR_OPEN_RANDOM);
    GUARD_RESULT_OSSL(ENGINE_set_id(e, "s2n_rand"), S2N_ERR_OPEN_RANDOM);
    GUARD_RESULT_OSSL(ENGINE_set_name(e, "s2n entropy generator"), S2N_ERR_OPEN_RANDOM);
    GUARD_RESULT_OSSL(ENGINE_set_flags(e, ENGINE_FLAGS_NO_REGISTER_ALL), S2N_ERR_OPEN_RANDOM);
    GUARD_RESULT_OSSL(ENGINE_set_init_function(e, s2n_openssl_compat_init), S2N_ERR_OPEN_RANDOM);
    GUARD_RESULT_OSSL(ENGINE_set_RAND(e, &s2n_openssl_rand_method), S2N_ERR_OPEN_RANDOM);
    GUARD_RESULT_OSSL(ENGINE_add(e), S2N_ERR_OPEN_RANDOM);
    GUARD_RESULT_OSSL(ENGINE_free(e) , S2N_ERR_OPEN_RANDOM);

    /* Use that engine for rand() */
    e = ENGINE_by_id("s2n_rand");
    ENSURE(e != NULL, S2N_ERR_OPEN_RANDOM);
    GUARD_RESULT_OSSL(ENGINE_init(e), S2N_ERR_OPEN_RANDOM);
    GUARD_RESULT_OSSL(ENGINE_set_default(e, ENGINE_METHOD_RAND), S2N_ERR_OPEN_RANDOM);
    GUARD_RESULT_OSSL(ENGINE_free(e), S2N_ERR_OPEN_RANDOM);
#endif

    return S2N_RESULT_OK;
}

S2N_RESULT s2n_rand_cleanup(void)
{
    ENSURE(entropy_fd != UNINITIALIZED_ENTROPY_FD, S2N_ERR_NOT_INITIALIZED);

    GUARD_AS_RESULT(close(entropy_fd));
    entropy_fd = UNINITIALIZED_ENTROPY_FD;

#if S2N_LIBCRYPTO_SUPPORTS_CUSTOM_RAND
    /* Cleanup our rand ENGINE in libcrypto */
    ENGINE *rand_engine = ENGINE_by_id("s2n_rand");
    if (rand_engine) {
        ENGINE_finish(rand_engine);
        ENGINE_free(rand_engine);
        ENGINE_cleanup();
    }
#endif

    return S2N_RESULT_OK;
}

S2N_RESULT s2n_rand_cleanup_thread(void)
{
    GUARD_AS_RESULT(s2n_drbg_wipe(&per_thread_private_drbg));
    GUARD_AS_RESULT(s2n_drbg_wipe(&per_thread_public_drbg));

    return S2N_RESULT_OK;
}

/*
 * This must only be used for unit tests. Any real use is dangerous and will be overwritten in s2n_defend_if_forked if
 * it is forked. This was added to support known answer tests that use OpenSSL and s2n_get_private_random_data directly.
 */
S2N_RESULT s2n_set_private_drbg_for_test(struct s2n_drbg drbg)
{
    ENSURE(s2n_in_unit_test(), S2N_ERR_NOT_IN_UNIT_TEST);
    GUARD_AS_RESULT(s2n_drbg_wipe(&per_thread_private_drbg));

    per_thread_private_drbg = drbg;
    return S2N_RESULT_OK;
}


bool s2n_cpu_supports_rdrand()
{
#if ((defined(__x86_64__) || defined(__i386__)) && (defined(__clang__) || S2N_GCC_VERSION_AT_LEAST(4,3,0)))
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

/*
 * volatile is important to prevent the compiler from
 * re-ordering or optimizing the use of RDRAND.
 */
S2N_RESULT s2n_get_rdrand_data(struct s2n_blob *out)
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

    GUARD_AS_RESULT(s2n_stuffer_init(&stuffer, out));
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

        ENSURE(success, S2N_ERR_RDRAND_FAILED);

        int data_to_fill = MIN(sizeof(output), space_remaining);

        GUARD_AS_RESULT(s2n_stuffer_write_bytes(&stuffer, output.u8, data_to_fill));
    }

    return S2N_RESULT_OK;
#else
    BAIL(S2N_ERR_UNSUPPORTED_CPU);
#endif
}
