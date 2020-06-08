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

/* Success signal value for OpenSSL functions */
#define _OSSL_SUCCESS 1

/**
 * The goal of s2n_safety is to provide helpers to perform common
 * checks, which help with code readability.
 */

/**
 * Sets the global `errno` and returns with a `S2N_RESULT_ERROR`
 */
#define BAIL( x )                                    do { _S2N_ERROR( ( x ) ); return S2N_RESULT_ERROR; } while (0)

/**
 * Sets the global `errno` and returns with a POSIX error (`-1`)
 */
#define BAIL_POSIX( x )                              do { _S2N_ERROR( ( x ) ); return S2N_FAILURE; } while (0)

/**
 * Sets the global `errno` and returns with a `NULL` pointer value
 */
#define BAIL_PTR( x )                                do { _S2N_ERROR( ( x ) ); return NULL; } while (0)

/**
 * Ensures the `condition` is `true`, otherwise the function will `BAIL` with an `error`
 */
#define ENSURE( condition , error )                  __S2N_ENSURE((condition), BAIL(error))

/**
 * Ensures the `result` is OK, otherwise the function will `BAIL` with an `error`
 */
#define ENSURE_OK( result , error )                  __S2N_ENSURE(s2n_result_is_ok(result), BAIL(error))

/**
 * Ensures `n` is greater than or equal to `min`, otherwise the function will `BAIL` with a `S2N_ERR_SAFETY` error
 */
#define ENSURE_GTE( n , min )                        ENSURE((n) >= (min), S2N_ERR_SAFETY)

/**
 * Ensures `n` is less than or equal to `max`, otherwise the function will `BAIL` with a `S2N_ERR_SAFETY` error
 */
#define ENSURE_LTE( n , max )                        ENSURE((n) <= (max), S2N_ERR_SAFETY)

/**
 * Ensures `n` is greater than `min`, otherwise the function will `BAIL` with a `S2N_ERR_SAFETY` error
 */
#define ENSURE_GT( n , min )                         ENSURE((n) > (min), S2N_ERR_SAFETY)

/**
 * Ensures `n` is less than `min`, otherwise the function will `BAIL` with a `S2N_ERR_SAFETY` error
 */
#define ENSURE_LT( n , max )                         ENSURE((n) < (max), S2N_ERR_SAFETY)

/**
 * Ensures `a` is equal to `b`, otherwise the function will `BAIL` with a `S2N_ERR_SAFETY` error
 */
#define ENSURE_EQ( a , b )                           ENSURE((a) == (b), S2N_ERR_SAFETY)

/**
 * Ensures `a` is not equal to `b`, otherwise the function will `BAIL` with a `S2N_ERR_SAFETY` error
 */
#define ENSURE_NE( a , b )                           ENSURE((a) != (b), S2N_ERR_SAFETY)

/**
 * Ensures the `condition` is `true`, otherwise the function will `BAIL_POSIX` with an `error`
 */
#define ENSURE_POSIX( condition , error )           __S2N_ENSURE((condition), BAIL_POSIX(error))

/**
 * Ensures the `condition` is `true`, otherwise the function will `BAIL_PTR` with an `error`
 */
#define ENSURE_PTR( condition , error )             __S2N_ENSURE((condition), BAIL_PTR(error))

/**
 * Ensures `x` is not `NULL`, otherwise the function will `BAIL_PTR` with an `error`
 */
#define ENSURE_REF_PTR( x )                         ENSURE_PTR(S2N_OBJECT_PTR_IS_READABLE(x), S2N_ERR_NULL)

/**
 * Ensures `x` is a readable reference, otherwise the function will `BAIL` with `S2N_ERR_NULL`
 */
#define ENSURE_REF( x )                             ENSURE(S2N_OBJECT_PTR_IS_READABLE(x), S2N_ERR_NULL)

/**
 * Ensures `x` is a readable reference, otherwise the function will `BAIL_POSIX` with `S2N_ERR_NULL`
 */
#define ENSURE_POSIX_REF( x )                       ENSURE_POSIX(S2N_OBJECT_PTR_IS_READABLE(x), S2N_ERR_NULL)

/**
 * Ensures `x` is a mutable reference, otherwise the function will `BAIL` with `S2N_ERR_NULL`
 */
#define ENSURE_MUT( x )                             ENSURE(S2N_OBJECT_PTR_IS_WRITABLE(x), S2N_ERR_NULL)

/**
 * Ensures `x` is a mutable reference, otherwise the function will `BAIL_POSIX` with `S2N_ERR_NULL`
 */
#define ENSURE_POSIX_MUT( x )                       ENSURE_POSIX(S2N_OBJECT_PTR_IS_WRITABLE(x), S2N_ERR_NULL)

/**
 * Ensures `min <= n <= max`
 */
#define ENSURE_INCLUSIVE_RANGE( min , n , max )      \
  do {                                               \
    __typeof( n ) __tmp_n = ( n );                   \
    ENSURE_GTE(__tmp_n, min);                        \
    ENSURE_LTE(__tmp_n, max);                        \
  } while(0)

/**
 * Ensures `min < n < max`
 */
#define ENSURE_EXCLUSIVE_RANGE( min , n , max )      \
  do {                                               \
    __typeof( n ) __tmp_n = ( n );                   \
    ENSURE_GT(__tmp_n, min);                         \
    ENSURE_LT(__tmp_n, max);                         \
  } while(0)

/**
 * Ensures the `condition` is `true`, otherwise the function will `BAIL` with a `S2N_ERR_PRECONDITION_VIOLATION` error
 */
#define PRECONDITION( condition )                   __S2N_ENSURE_CONDITION((condition), BAIL(S2N_ERR_PRECONDITION_VIOLATION))

/**
 * Ensures the `condition` is `true`, otherwise the function will `BAIL` with a `S2N_ERR_POSTCONDITION_VIOLATION` error
 */
#define POSTCONDITION( condition )                  __S2N_ENSURE_CONDITION((condition), BAIL(S2N_ERR_POSTCONDITION_VIOLATION))

/**
 * Ensures the `condition` is `true`, otherwise the function will `BAIL_POSIX` with a `S2N_ERR_PRECONDITION_VIOLATION` error
 */
#define PRECONDITION_POSIX( condition )             __S2N_ENSURE_CONDITION((condition), BAIL_POSIX(S2N_ERR_PRECONDITION_VIOLATION))

/**
 * Ensures the `condition` is `true`, otherwise the function will `BAIL_POSIX` with a `S2N_ERR_POSTCONDITION_VIOLATION` error
 */
#define POSTCONDITION_POSIX( condition )            __S2N_ENSURE_CONDITION((condition), BAIL_POSIX(S2N_ERR_POSTCONDITION_VIOLATION))

/**
 * Ensures `x` is not an error, otherwise the function will return an error signal
 *
 * Note: this currently accepts POSIX error signals but will transition to accept s2n_result
 */
#define GUARD( x )                                  GUARD_POSIX(x)

/**
 * Ensures `x` is not an error, otherwise goto `label`
 *
 * Note: this currently accepts POSIX error signals but will transition to accept s2n_result
 */
#define GUARD_GOTO( x , label )                     GUARD_POSIX_GOTO((x), (label))

/**
 * Ensures `x` is not an error, otherwise the function will return `NULL`
 *
 * Note: this currently accepts POSIX error signals but will transition to accept s2n_result
 */
#define GUARD_PTR( x )                              GUARD_POSIX_PTR(x)

/**
 * Ensures `x` is not `NULL`, otherwise the function will return an error signal
 *
 * Note: this currently accepts POSIX error signals but will transition to accept s2n_result
 */
#define GUARD_NONNULL( x )                          GUARD_POSIX_NONNULL(x)

/**
 * Ensures `x` is not `NULL`, otherwise goto `label`
 *
 * Note: this currently accepts POSIX error signals but will transition to accept s2n_result
 */
#define GUARD_NONNULL_GOTO( x , label )             __S2N_ENSURE((x) != NULL, goto label)

/**
 * Ensures `x` is not `NULL`, otherwise the function will return `NULL`
 *
 * Note: this currently accepts POSIX error signals but will transition to accept s2n_result
 */
#define GUARD_NONNULL_PTR( x )                      __S2N_ENSURE((x) != NULL, return NULL)

/**
 * Ensures `x` is not a OpenSSL error, otherwise the function will return an error signal
 *
 * Note: this currently accepts POSIX error signals but will transition to accept s2n_result
 */
#define GUARD_OSSL( x, error )                      GUARD_POSIX_OSSL((x), (error))

/**
 * Ensures `x` is ok, otherwise the function will return an `S2N_RESULT_ERROR`
 */
#define GUARD_RESULT( x )                           __S2N_ENSURE(s2n_result_is_ok(x), return S2N_RESULT_ERROR)

/**
 * Ensures `x` is ok, otherwise goto `label`
 */
#define GUARD_RESULT_GOTO( x, label )               __S2N_ENSURE(s2n_result_is_ok(x), goto label)

/**
 * Ensures `x` is ok, otherwise the function will return `NULL`
 */
#define GUARD_RESULT_PTR( x )                       __S2N_ENSURE(s2n_result_is_ok(x), return NULL)

/**
 * Ensures `x` is not `NULL`, otherwise the function will return an `S2N_RESULT_ERROR`
 */
#define GUARD_RESULT_NONNULL( x )                   __S2N_ENSURE((x) != NULL, return S2N_RESULT_ERROR)

/**
 * Ensures `x` is not a OpenSSL error, otherwise the function will `BAIL` with `error`
 */
/* TODO: use the OSSL error code in error reporting https://github.com/awslabs/s2n/issues/705 */
#define GUARD_RESULT_OSSL( x , error )              ENSURE((x) == _OSSL_SUCCESS, error)

/**
 * Ensures `x` is not a POSIX error, otherwise return a POSIX error
 */
#define GUARD_POSIX( x )                            __S2N_ENSURE((x) >= S2N_SUCCESS, return S2N_FAILURE)

/**
 * Ensures `x` is strictly not a POSIX error (`-1`), otherwise goto `label`
 */
#define GUARD_POSIX_STRICT( x )                     __S2N_ENSURE((x) == S2N_SUCCESS, return S2N_FAILURE)

/**
 * Ensures `x` is not a POSIX error, otherwise goto `label`
 */
#define GUARD_POSIX_GOTO( x , label )               __S2N_ENSURE((x) >= S2N_SUCCESS, goto label)

/**
 * Ensures `x` is not a POSIX error, otherwise the function will return `NULL`
 */
#define GUARD_POSIX_PTR( x )                        __S2N_ENSURE((x) >= S2N_SUCCESS, return NULL)

/**
 * Ensures `x` is not `NULL`, otherwise the function will return a POSIX error (`-1`)
 */
#define GUARD_POSIX_NONNULL( x )                    __S2N_ENSURE((x) != NULL, return S2N_FAILURE)

/**
 * Ensures `x` is not a OpenSSL error, otherwise the function will `BAIL` with `error`
 */
/* TODO: use the OSSL error code in error reporting https://github.com/awslabs/s2n/issues/705 */
#define GUARD_POSIX_OSSL( x , error )               ENSURE_POSIX((x) == _OSSL_SUCCESS, error)

/**
 * Ensures `x` is not a POSIX error, otherwise the function will return a `S2N_RESULT_ERROR`
 */
#define GUARD_AS_RESULT( x )                        __S2N_ENSURE((x) >= S2N_SUCCESS, return S2N_RESULT_ERROR)

/**
 * Ensures `x` is OK, otherwise the function will return a POSIX error (`-1`)
 */
#define GUARD_AS_POSIX( x )                         __S2N_ENSURE(s2n_result_is_ok(x), return S2N_FAILURE)

/**
 * Performs a safe memcpy
 */
#define CHECKED_MEMCPY( d , s , n )                 __S2N_ENSURE_SAFE_MEMCPY((d), (s), (n), GUARD_RESULT_NONNULL)

/**
 * Performs a safe memset
 */
#define CHECKED_MEMSET( d , c , n )                 __S2N_ENSURE_SAFE_MEMSET((d), (c), (n), ENSURE_REF)

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
extern int s2n_constant_time_equals(const uint8_t * a, const uint8_t * b, uint32_t len);

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

/* START COMPATIBILITY LAYER */

/**
 * NOTE: This will be removed once everything is using s2n_result
 */

/* `NULL` check a pointer */

/* Note: this macro is replaced by ENSURE_POSIX_REF */
#define notnull_check( ptr )                        ENSURE_POSIX_REF(ptr)
/* Note: this macro is replaced by ENSURE_REF_PTR */
#define notnull_check_ptr( ptr )                    ENSURE_REF_PTR(ptr)

/* Range check a number */
#define gte_check( n , min )                        ENSURE_POSIX((n) >= (min), S2N_ERR_SAFETY)
#define lte_check( n , max )                        ENSURE_POSIX((n) <= (max), S2N_ERR_SAFETY)
#define gt_check( n , min )                         ENSURE_POSIX((n) > (min), S2N_ERR_SAFETY)
#define lt_check( n , max )                         ENSURE_POSIX((n) < (max), S2N_ERR_SAFETY)
#define eq_check( a , b )                           ENSURE_POSIX((a) == (b), S2N_ERR_SAFETY)
#define ne_check( a , b )                           ENSURE_POSIX((a) != (b), S2N_ERR_SAFETY)
#define inclusive_range_check( low, n, high )       \
  do  {                                             \
    __typeof( n ) __tmp_n = ( n );                  \
    gte_check(__tmp_n, low);                        \
    lte_check(__tmp_n, high);                       \
  } while (0)
#define exclusive_range_check( low, n, high )       \
  do {                                              \
    __typeof( n ) __tmp_n = ( n );                  \
    gt_check(__tmp_n, low);                         \
    lt_check(__tmp_n, high);                        \
  } while (0)

#define memcpy_check( d , s , n )                   __S2N_ENSURE_SAFE_MEMCPY((d), (s), (n), GUARD_POSIX_NONNULL)
/* This will fail to build if d is an array. Cast the array to a pointer first! */
#define memset_check( d , c , n )                   __S2N_ENSURE_SAFE_MEMSET((d), (c), (n), ENSURE_POSIX_REF)

/* END COMPATIBILITY LAYER */
