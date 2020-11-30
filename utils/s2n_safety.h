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

#include <string.h>
#include <sys/types.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>

#include "error/s2n_errno.h"
#include "utils/s2n_ensure.h"
#include "utils/s2n_result.h"
#include "utils/s2n_safety_macros.h"

/**
 * The goal of s2n_safety is to provide helpers to perform common
 * checks, which help with code readability.
 */

/**
 * Marks a case of a switch statement as able to fall through to the next case
 */
#if defined(S2N_FALL_THROUGH_SUPPORTED)
#    define FALL_THROUGH __attribute__((fallthrough))
#else
#    define FALL_THROUGH ((void)0)
#endif

/* Returns `true` if s2n is in unit test mode, `false` otherwise */
bool s2n_in_unit_test();

/* Sets whether s2n is in unit test mode */
int s2n_in_unit_test_set(bool newval);

#define S2N_IN_INTEG_TEST ( getenv("S2N_INTEG_TEST") != NULL )
#define S2N_IN_TEST ( s2n_in_unit_test() || S2N_IN_INTEG_TEST )

/**
 * Get the process id
 *
 * Returns:
 *  The process ID of the current process
 */
extern pid_t s2n_actual_getpid();

/* Returns 1 if a and b are equal, in constant time */
extern bool s2n_constant_time_equals(const uint8_t * a, const uint8_t * b, const uint32_t len);

/* Copy src to dst, or don't copy it, in constant time */
extern int s2n_constant_time_copy_or_dont(uint8_t * dst, const uint8_t * src, uint32_t len, uint8_t dont);

/* If src contains valid PKCS#1 v1.5 padding of exactly expectlen bytes, decode
 * it into dst, otherwise leave dst alone, in constant time.
 * Always returns zero. */
extern int s2n_constant_time_pkcs1_unpad_or_dont(uint8_t * dst, const uint8_t * src, uint32_t srclen, uint32_t expectlen);

/**
 * Runs _thecleanup function on _thealloc once _thealloc went out of scope
 */
#define DEFER_CLEANUP(_thealloc, _thecleanup) \
   __attribute__((cleanup(_thecleanup))) _thealloc
/**
 * Often we want to free memory on an error, but not on a success.
 * We do this by declaring a variable with DEFER_CLEANUP, then zeroing
 * that variable after success to prevent DEFER_CLEANUP from accessing
 * and freeing any memory it allocated.
 *
 * This pattern is not intuitive, so a named macro makes it more readable.
 */
#define ZERO_TO_DISABLE_DEFER_CLEANUP(_thealloc) memset(&_thealloc, 0, sizeof(_thealloc))

/* Creates cleanup function for pointers from function func which accepts a pointer.
 * This is useful for DEFER_CLEANUP as it passes &_thealloc into _thecleanup function,
 * so if _thealloc is a pointer _thecleanup will receive a pointer to a pointer.*/
#define DEFINE_POINTER_CLEANUP_FUNC(type, func)             \
  static inline void func##_pointer(type *p) {              \
    if (p && *p)                                            \
      func(*p);                                             \
  }                                                         \
  struct __useless_struct_to_allow_trailing_semicolon__

#define s2n_array_len(array) ((array != NULL) ? (sizeof(array) / sizeof(array[0])) : 0)

extern int s2n_mul_overflow(uint32_t a, uint32_t b, uint32_t* out);

/**
 * Rounds "initial" up to a multiple of "alignment", and stores the result in "out".
 * Raises an error if overflow would occur.
 * NOT CONSTANT TIME.
 */
extern int s2n_align_to(uint32_t initial, uint32_t alignment, uint32_t* out);
extern int s2n_add_overflow(uint32_t a, uint32_t b, uint32_t* out);
extern int s2n_sub_overflow(uint32_t a, uint32_t b, uint32_t* out);


/* START COMPATIBILITY LAYER */

/**
 * NOTE: This will be removed once everything is using the new safety macro
 *       naming conventions
 */

/**
 * Sets the global `errno` and returns with a `S2N_RESULT_ERROR`
 */
#define BAIL( x )                                    RESULT_BAIL(x)

/**
 * Sets the global `errno` and returns with a POSIX error (`-1`)
 */
#define BAIL_POSIX( x )                              POSIX_BAIL(x)

/**
 * Sets the global `errno` and returns with a `NULL` pointer value
 */
#define BAIL_PTR( x )                                PTR_BAIL(x)

/**
 * Ensures the `condition` is `true`, otherwise the function will `BAIL` with an `error`
 */
#define ENSURE( condition , error )                  RESULT_ENSURE((condition), (error))

/**
 * Ensures the `result` is OK, otherwise the function will `BAIL` with an `error`
 */
#define ENSURE_OK( result , error )                  RESULT_ENSURE_OK((result), (error))

/**
 * Ensures `n` is greater than or equal to `min`, otherwise the function will `BAIL` with a `S2N_ERR_SAFETY` error
 */
#define ENSURE_GTE( n , min )                        RESULT_ENSURE_GTE((n), (min))

/**
 * Ensures `n` is less than or equal to `max`, otherwise the function will `BAIL` with a `S2N_ERR_SAFETY` error
 */
#define ENSURE_LTE( n , max )                        RESULT_ENSURE_LTE((n), (max))

/**
 * Ensures `n` is greater than `min`, otherwise the function will `BAIL` with a `S2N_ERR_SAFETY` error
 */
#define ENSURE_GT( n , min )                         RESULT_ENSURE_GT((n), (min))

/**
 * Ensures `n` is less than `min`, otherwise the function will `BAIL` with a `S2N_ERR_SAFETY` error
 */
#define ENSURE_LT( n , max )                         RESULT_ENSURE_LT((n), (max))

/**
 * Ensures `a` is equal to `b`, otherwise the function will `BAIL` with a `S2N_ERR_SAFETY` error
 */
#define ENSURE_EQ( a , b )                           RESULT_ENSURE_EQ((a), (b))

/**
 * Ensures `a` is not equal to `b`, otherwise the function will `BAIL` with a `S2N_ERR_SAFETY` error
 */
#define ENSURE_NE( a , b )                           RESULT_ENSURE_NE((a), (b))

/**
 * Ensures the `condition` is `true`, otherwise the function will `BAIL_POSIX` with an `error`
 */
#define ENSURE_POSIX( condition , error )           POSIX_ENSURE((condition), (error))

/**
 * Ensures the `condition` is `true`, otherwise the function will `BAIL_PTR` with an `error`
 */
#define ENSURE_PTR( condition , error )             PTR_ENSURE((condition), (error))

/**
 * Ensures `x` is not `NULL`, otherwise the function will `BAIL_PTR` with an `error`
 */
#define ENSURE_REF_PTR( x )                         PTR_ENSURE_REF(x)

/**
 * Ensures `x` is a readable reference, otherwise the function will `BAIL` with `S2N_ERR_NULL`
 */
#define ENSURE_REF( x )                             RESULT_ENSURE_REF(x)

/**
 * Ensures `x` is a readable reference, otherwise the function will `BAIL_POSIX` with `S2N_ERR_NULL`
 */
#define ENSURE_POSIX_REF( x )                       POSIX_ENSURE_REF(x)

/**
 * Ensures `x` is a mutable reference, otherwise the function will `BAIL` with `S2N_ERR_NULL`
 */
#define ENSURE_MUT( x )                             RESULT_ENSURE_MUT(x)

/**
 * Ensures `x` is a mutable reference, otherwise the function will `BAIL_POSIX` with `S2N_ERR_NULL`
 */
#define ENSURE_POSIX_MUT( x )                       POSIX_ENSURE_MUT(x)

/**
 * Ensures `min <= n <= max`
 */
#define ENSURE_INCLUSIVE_RANGE( min , n , max )     RESULT_ENSURE_INCLUSIVE_RANGE((min), (n), (max))

/**
 * Ensures `min < n < max`
 */
#define ENSURE_EXCLUSIVE_RANGE( min , n , max )     RESULT_ENSURE_EXCLUSIVE_RANGE((min), (n), (max))

/**
 * Ensures the `result` is `S2N_RESULT_OK`, otherwise the function will return an error signal
 */
#define PRECONDITION( result )                      RESULT_PRECONDITION(result)

/**
 * Ensures the `result` is `S2N_RESULT_OK`, otherwise the function will return an error signal
 */
#define POSTCONDITION( result )                     RESULT_POSTCONDITION(result)

/**
 * Ensures the `result` is `S2N_RESULT_OK`, otherwise the function will return an error signal
 */
#define PRECONDITION_POSIX( result )                POSIX_PRECONDITION(result)

/**
 * Ensures the `result` is `S2N_RESULT_OK`, otherwise the function will return an error signal
 */
#define POSTCONDITION_POSIX( result )               POSIX_POSTCONDITION(result)

/**
 * Ensures the `condition` is `true`, otherwise the function will `BAIL` with an `error`.
 * When the code is built in debug mode, they are checked.
 * When the code is built in production mode, they are ignored.
 */
#define DEBUG_ENSURE( condition, error )            RESULT_DEBUG_ENSURE((condition), (error))

/**
 * Ensures the `condition` is `true`, otherwise the function will `BAIL_POSIX` with an `error`.
 * When the code is built in debug mode, they are checked.
 * When the code is built in production mode, they are ignored.
 */
#define DEBUG_ENSURE_POSIX( condition, error )      POSIX_DEBUG_ENSURE((condition), (error))

/**
 * Ensures `x` is not an error, otherwise the function will return an error signal
 *
 * Note: this currently accepts POSIX error signals but will transition to accept s2n_result
 */
#define GUARD( x )                                  POSIX_GUARD(x)

/**
 * Ensures `x` is not an error, otherwise the function will return `NULL`
 *
 * Note: this currently accepts POSIX error signals but will transition to accept s2n_result
 */
#define GUARD_PTR( x )                              PTR_GUARD_POSIX(x)

/**
 * Ensures `x` is not `NULL`, otherwise the function will return an error signal
 *
 * Note: this currently accepts POSIX error signals but will transition to accept s2n_result
 */
#define GUARD_NONNULL( x )                          POSIX_GUARD_PTR(x)

/**
 * Ensures `x` is not `NULL`, otherwise the function will return `NULL`
 */
#define GUARD_NONNULL_PTR( x )                      PTR_GUARD(x)

/**
 * Ensures `x` is not a OpenSSL error, otherwise the function will return an error signal
 *
 * Note: this currently accepts POSIX error signals but will transition to accept s2n_result
 */
#define GUARD_OSSL( x, error )                      POSIX_GUARD_OSSL((x), (error))

/**
 * Ensures `x` is ok, otherwise the function will return an `S2N_RESULT_ERROR`
 */
#define GUARD_RESULT( x )                           RESULT_GUARD(x)

/**
 * Ensures `x` is ok, otherwise the function will return `NULL`
 */
#define GUARD_RESULT_PTR( x )                       PTR_GUARD_RESULT(x)

/**
 * Ensures `x` is not `NULL`, otherwise the function will return an `S2N_RESULT_ERROR`
 */
#define GUARD_RESULT_NONNULL( x )                   RESULT_GUARD_PTR(x)

/**
 * Ensures `x` is not a OpenSSL error, otherwise the function will `BAIL` with `error`
 */
/* TODO: use the OSSL error code in error reporting https://github.com/awslabs/s2n/issues/705 */
#define GUARD_RESULT_OSSL( x , error )              RESULT_GUARD_OSSL((x), (error))

/**
 * Ensures `x` is not a POSIX error, otherwise return a POSIX error
 */
#define GUARD_POSIX( x )                            POSIX_GUARD(x)

/**
 * Ensures `x` is not a POSIX error, otherwise the function will return `NULL`
 */
#define GUARD_POSIX_PTR( x )                        PTR_GUARD_POSIX(x)

/**
 * Ensures `x` is not `NULL`, otherwise the function will return a POSIX error (`-1`)
 */
#define GUARD_POSIX_NONNULL( x )                    POSIX_GUARD_PTR(x)

/**
 * Ensures `x` is not a OpenSSL error, otherwise the function will `BAIL` with `error`
 */
/* TODO: use the OSSL error code in error reporting https://github.com/awslabs/s2n/issues/705 */
#define GUARD_POSIX_OSSL( x , error )               POSIX_GUARD_OSSL((x), (error))

/**
 * Ensures `x` is not a POSIX error, otherwise the function will return a `S2N_RESULT_ERROR`
 */
#define GUARD_AS_RESULT( x )                        RESULT_GUARD_POSIX(x)

/**
 * Ensures `x` is OK (S2N_RESULT), otherwise the function will return a POSIX error (`-1`)
 */
#define GUARD_AS_POSIX( x )                         POSIX_GUARD_RESULT(x)

/**
 * Performs a safe memcpy
 */
#define CHECKED_MEMCPY( d , s , n )                 RESULT_CHECKED_MEMCPY((d), (s), (n))

/**
 * Performs a safe memset
 */
#define CHECKED_MEMSET( d , c , n )                 RESULT_CHECKED_MEMSET((d), (c), (n))

/* `NULL` check a pointer */

/* Note: this macro is replaced by POSIX_ENSURE_REF */
#define notnull_check(ptr)                          POSIX_ENSURE_REF(ptr)
/* Note: this macro is replaced by PTR_ENSURE_REF */
#define notnull_check_ptr(ptr)                      PTR_ENSURE_REF(ptr)

/* Range check a number */
#define gte_check( n , min )                        POSIX_ENSURE_GTE((n), (min))
#define lte_check( n , max )                        POSIX_ENSURE_LTE((n), (max))
#define gt_check( n , min )                         POSIX_ENSURE_GT((n), (min))
#define lt_check( n , max )                         POSIX_ENSURE_LT((n), (max))
#define eq_check( a , b )                           POSIX_ENSURE_EQ((a), (b))
#define ne_check( a , b )                           POSIX_ENSURE_NE((a), (b))
#define inclusive_range_check( low, n, high )       POSIX_ENSURE_INCLUSIVE_RANGE((low), (n), (high))
#define exclusive_range_check( low, n, high )       POSIX_ENSURE_EXCLUSIVE_RANGE((low), (n), (high))

#define memcpy_check( d , s , n )                   POSIX_CHECKED_MEMCPY((d), (s), (n))
/* This will fail to build if d is an array. Cast the array to a pointer first! */
#define memset_check( d , c , n )                   POSIX_CHECKED_MEMSET((d), (c), (n))

/* END COMPATIBILITY LAYER */
