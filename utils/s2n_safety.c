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

#define _GNU_SOURCE             /* For syscall on Linux */
#undef _POSIX_C_SOURCE          /* For syscall() on Mac OS X */

#include <unistd.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <stdint.h>

#include "s2n_annotations.h"

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
int s2n_constant_time_equals(const uint8_t * a, const uint8_t * b, uint32_t len)
{
    S2N_PUBLIC_INPUT(a);
    S2N_PUBLIC_INPUT(b);
    S2N_PUBLIC_INPUT(len);
    
    uint8_t xor = 0;
    for (int i = 0; i < len; i++) {
        /* Invariants must hold for each execution of the loop
	 * and at loop exit, hence the <= */ 
        S2N_INVARIENT(i <= len);
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
    
    uint8_t mask = ((uint_fast16_t)((uint_fast16_t)(dont) - 1)) >> 8;

    /* dont = 0 : mask = 0xff */
    /* dont > 0 : mask = 0x00 */

    for (int i = 0; i < len; i++) {
        uint8_t old = dest[i];
        uint8_t diff = (old ^ src[i]) & mask;
        dest[i] = old ^ diff;
    }

    return 0;
}
