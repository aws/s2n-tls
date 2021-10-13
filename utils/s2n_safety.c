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

#define _GNU_SOURCE             /* For syscall on Linux */
#undef _POSIX_C_SOURCE          /* For syscall() on Mac OS X */

#include <unistd.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <stdint.h>
#include <stdio.h>

#include "utils/s2n_annotations.h"
#include "utils/s2n_safety.h"

/**
 * Get the process id
 *
 * Returns:
 *  The process ID of the current process
 */
pid_t s2n_actual_getpid()
{
#if defined(__GNUC__) && defined(SYS_getpid)
    /* http://yarchive.net/comp/linux/getpid_caching.html */
    return (pid_t) syscall(SYS_getpid);
#else
    return getpid();
#endif
}

/**
 * Given arrays "a" and "b" of length "len", determine whether they
 * hold equal contents.
 *
 * The execution time of this function is independent of the values
 * stored in the arrays.
 *
 * Timing may depend on the length of the arrays, and on the location
 * of the arrays in memory (e.g. if a buffer has been paged out, this
 * will affect the timing of this function).
 *
 * Returns:
 *  Whether all bytes in arrays "a" and "b" are identical
 */
bool s2n_constant_time_equals(const uint8_t * a, const uint8_t * b, const uint32_t len)
{
    S2N_PUBLIC_INPUT(a);
    S2N_PUBLIC_INPUT(b);
    S2N_PUBLIC_INPUT(len);
    POSIX_ENSURE((a == NULL) || S2N_MEM_IS_READABLE(a, len), S2N_ERR_SAFETY);
    POSIX_ENSURE((b == NULL) || S2N_MEM_IS_READABLE(b, len), S2N_ERR_SAFETY);

    if (len != 0 && (a == NULL || b == NULL)) {
        return false;
    }

    uint8_t xor = 0;
    for (uint32_t i = 0; i < len; i++) {
        /* Invariants must hold for each execution of the loop
	 * and at loop exit, hence the <= */
        S2N_INVARIANT(i <= len);
        xor |= a[i] ^ b[i];
    }

    return !xor;
}

/**
 * Given arrays "dest" and "src" of length "len", conditionally copy "src" to "dest"
 * The execution time of this function is independent of the values
 * stored in the arrays, and of whether the copy occurs.
 *
 * Timing may depend on the length of the arrays, and on the location
 * of the arrays in memory (e.g. if a buffer has been paged out, this
 * will affect the timing of this function).
 *
 */
int s2n_constant_time_copy_or_dont(uint8_t * dest, const uint8_t * src, uint32_t len, uint8_t dont)
{
    S2N_PUBLIC_INPUT(dest);
    S2N_PUBLIC_INPUT(src);
    S2N_PUBLIC_INPUT(len);

    uint8_t mask = (((0xFFFF & dont) - 1) >> 8) & 0xFF;

    /* dont = 0 : mask = 0xff */
    /* dont > 0 : mask = 0x00 */

    for (uint32_t i = 0; i < len; i++) {
        uint8_t old = dest[i];
        uint8_t diff = (old ^ src[i]) & mask;
        dest[i] = old ^ diff;
    }

    return 0;
}

/* If src contains valid PKCS#1 v1.5 padding of exactly expectlen bytes, decode
 * it into dst, otherwise leave dst alone. Execution time is independent of the
 * content of src, but may depend on srclen/expectlen.
 *
 * Normally, one would fill dst with random bytes before calling this function.
 */
int s2n_constant_time_pkcs1_unpad_or_dont(uint8_t * dst, const uint8_t * src, uint32_t srclen, uint32_t expectlen)
{
    S2N_PUBLIC_INPUT(dst);
    S2N_PUBLIC_INPUT(src);
    S2N_PUBLIC_INPUT(srclen);
    S2N_PUBLIC_INPUT(expectlen);

    /* Before doing anything else, some basic sanity checks on input lengths */
    if (srclen < expectlen + 3) {
        /* Not enough room for PKCS#1v1.5 padding, so treat it as bad padding */
        return 0;
    }

    /* First, determine (in constant time) whether the padding is valid.
     * If the padding is valid we expect that:
     * Bytes 0 and 1 will equal 0x00 and 0x02
     * Bytes (srclen-expectlen-1) will be zero
     * Bytes 2 through (srclen-expectlen-1) will be nonzero
     */
    uint8_t dont_copy = 0;
    const uint8_t *start_of_data = src + srclen - expectlen;

    dont_copy |= src[0] ^ 0x00;
    dont_copy |= src[1] ^ 0x02;
    dont_copy |= *(start_of_data-1) ^ 0x00;

    for (uint32_t i = 2; i < srclen - expectlen - 1; i++) {
        /* Note! We avoid using logical NOT (!) here; while in practice
         * many compilers will use constant-time sequences for this operator,
         * at least on x86 (e.g. cmp -> setcc, or vectorized pcmpeq), this is
         * not guaranteed to hold, and some architectures might not have a
         * convenient mechanism for generating a branchless logical not. */
        uint8_t mask = (((0xFFFF & src[i]) - 1) >> 8) & 0xFF;
        /* src[i] = 0 : mask = 0xff */
        /* src[i] > 0 : mask = 0x00 */
        dont_copy |= mask;
    }

    s2n_constant_time_copy_or_dont(dst, start_of_data, expectlen, dont_copy);

    return 0;
}

static bool s_s2n_in_unit_test = false;

bool s2n_in_unit_test()
{
    return s_s2n_in_unit_test;
}

int s2n_in_unit_test_set(bool newval)
{
    s_s2n_in_unit_test = newval;
    return S2N_SUCCESS;
}

int s2n_align_to(uint32_t initial, uint32_t alignment, uint32_t* out)
{
    POSIX_ENSURE_REF(out);
    POSIX_ENSURE(alignment != 0, S2N_ERR_SAFETY);
    if (initial == 0) {
        *out = 0;
        return S2N_SUCCESS;
    }
    const uint64_t i = initial;
    const uint64_t a = alignment;
    const uint64_t result = a * (((i - 1) / a) + 1);
    POSIX_ENSURE(result <= UINT32_MAX, S2N_ERR_INTEGER_OVERFLOW);
    *out = (uint32_t) result;
    return S2N_SUCCESS;
}

int s2n_mul_overflow(uint32_t a, uint32_t b, uint32_t* out)
{
    POSIX_ENSURE_REF(out);
    const uint64_t result = ((uint64_t) a) * ((uint64_t) b);
    POSIX_ENSURE(result <= UINT32_MAX, S2N_ERR_INTEGER_OVERFLOW);
    *out = (uint32_t) result;
    return S2N_SUCCESS;
}

int s2n_add_overflow(uint32_t a, uint32_t b, uint32_t* out)
{
    POSIX_ENSURE_REF(out);
    uint64_t result = ((uint64_t) a) + ((uint64_t) b);
    POSIX_ENSURE(result <= UINT32_MAX, S2N_ERR_INTEGER_OVERFLOW);
    *out = (uint32_t) result;
    return S2N_SUCCESS;
}

int s2n_sub_overflow(uint32_t a, uint32_t b, uint32_t* out)
{
    POSIX_ENSURE_REF(out);
    POSIX_ENSURE(a >= b, S2N_ERR_INTEGER_OVERFLOW);
    *out = a - b;
    return S2N_SUCCESS;
}
