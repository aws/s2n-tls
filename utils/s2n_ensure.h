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

#pragma once

#define s2n_likely(x) __builtin_expect(!!(x), 1)
#define s2n_unlikely(x) __builtin_expect(!!(x), 0)

/**
 * s2n_ensure provides low-level safety check functionality
 *
 * This should only consumed directly by s2n_safety.
 *
 * Note: This module can be replaced by static analyzer implementation
 *       to insert additional safety checks.
 */

/**
 * Ensures `cond` is true, otherwise `action` will be performed
 */
#define __S2N_ENSURE( cond, action ) do {if ( !(cond) ) { action; }} while (0)

#define __S2N_ENSURE_LIKELY( cond, action ) do {if ( s2n_unlikely( !(cond) ) ) { action; }} while (0)

#ifdef NDEBUG
#define __S2N_ENSURE_DEBUG( cond, action ) do {} while (0)
#else
#define __S2N_ENSURE_DEBUG( cond, action ) __S2N_ENSURE_LIKELY((cond), action)
#endif

#define __S2N_ENSURE_PRECONDITION( result ) (s2n_likely(s2n_result_is_ok(result)) ? S2N_RESULT_OK : S2N_RESULT_ERROR)

#ifdef NDEBUG
#define __S2N_ENSURE_POSTCONDITION( result ) (S2N_RESULT_OK)
#else
#define __S2N_ENSURE_POSTCONDITION( result ) (s2n_likely(s2n_result_is_ok(result)) ? S2N_RESULT_OK : S2N_RESULT_ERROR)
#endif

#define __S2N_ENSURE_SAFE_MEMCPY( d , s , n , guard )                            \
  do {                                                                           \
    __typeof( n ) __tmp_n = ( n );                                               \
    if ( s2n_likely( __tmp_n ) ) {                                               \
      void *r = s2n_ensure_memcpy_trace( (d), (s) , (__tmp_n), _S2N_DEBUG_LINE); \
      guard(r);                                                                  \
    }                                                                            \
  } while(0)

#define __S2N_ENSURE_SAFE_MEMSET( d , c , n , guard )                            \
  do {                                                                           \
    __typeof( n ) __tmp_n = ( n );                                               \
    if ( s2n_likely( __tmp_n ) ) {                                               \
      __typeof( d ) __tmp_d = ( d );                                             \
      guard( __tmp_d );                                                          \
      memset( __tmp_d, (c), __tmp_n);                                            \
    }                                                                            \
  } while(0)

/**
 * `restrict` is a part of the c99 standard and will work with any C compiler. If you're trying to
 * compile with a C++ compiler `restrict` is invalid. However some C++ compilers support the behavior
 * of `restrict` using the `__restrict__` keyword. Therefore if the compiler supports `__restrict__`
 * use it.
 *
 * This is helpful for the benchmarks in tests/benchmark which use Google's Benchmark library and
 * are all written in C++.
 *
 * https://gcc.gnu.org/onlinedocs/gcc/Restricted-Pointers.html
 *
 */
#if defined(S2N___RESTRICT__SUPPORTED)
extern void* s2n_ensure_memcpy_trace(void *__restrict__ to, const void *__restrict__ from, size_t size, const char *debug_str);
#else
extern void* s2n_ensure_memcpy_trace(void *restrict to, const void *restrict from, size_t size, const char *debug_str);
#endif
