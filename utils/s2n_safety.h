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

#pragma once

#include <string.h>
#include <sys/types.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>

#include "error/s2n_errno.h"

/* NULL check a pointer */
#define notnull_check( ptr )           do { if ( (ptr) == NULL ) { S2N_ERROR(S2N_ERR_NULL); } } while(0)
#define notnull_check_ptr( ptr )       do { if ( (ptr) == NULL ) { S2N_ERROR_PTR(S2N_ERR_NULL); } } while(0)

static inline void* trace_memcpy_check(void *restrict to, const void *restrict from, size_t size, const char *debug_str)
{
    if (to == NULL || from == NULL) {
        s2n_errno = S2N_ERR_NULL;
        s2n_debug_str = debug_str;
        return NULL;
    }

    return memcpy(to, from, size);
}

/* Check memcpy and memset's arguments, if these are not right, log an error
 */
#define memcpy_check( d, s, n )                                             \
  do {                                                                      \
    __typeof( n ) __tmp_n = ( n );                                          \
    if ( __tmp_n ) {                                                        \
      void *r = trace_memcpy_check( (d), (s) , (__tmp_n), _S2N_DEBUG_LINE); \
      if (r == NULL) { return -1; }                                         \
    }                                                                       \
  } while(0)

#define memcpy_check_ptr( d, s, n )                                         \
  do {                                                                      \
    __typeof( n ) __tmp_n = ( n );                                          \
    if ( __tmp_n ) {                                                        \
      void *r = trace_memcpy_check( (d), (s) , (__tmp_n), _S2N_DEBUG_LINE); \
      if (r == NULL) { return NULL; }                                       \
    }                                                                       \
  } while(0)

#define memset_check( d, c, n )                                             \
  do {                                                                      \
    __typeof( n ) __tmp_n = ( n );                                          \
    if ( __tmp_n ) {                                                        \
      __typeof( d ) __tmp_d = ( d );                                        \
      notnull_check( __tmp_d );                                             \
      memset( __tmp_d, (c), __tmp_n);                                       \
    }                                                                       \
  } while(0)

#define char_to_digit(c, d)  do { if(!isdigit(c)) { S2N_ERROR(S2N_ERR_SAFETY); } d = c - '0'; } while(0)

/* Range check a number */
#define gte_check(n, min)  do { if ( (n) < min ) { S2N_ERROR(S2N_ERR_SAFETY); } } while(0)
#define lte_check(n, max)  do { if ( (n) > max ) { S2N_ERROR(S2N_ERR_SAFETY); } } while(0)
#define gt_check(n, min)  do { if ( (n) <= min ) { S2N_ERROR(S2N_ERR_SAFETY); } } while(0)
#define lt_check(n, max)  do { if ( (n) >= max ) { S2N_ERROR(S2N_ERR_SAFETY); } } while(0)
#define eq_check(a, b)  do { if ( (a) != (b) ) { S2N_ERROR(S2N_ERR_SAFETY); } } while(0)
#define ne_check(a, b)  do { if ( (a) == (b) ) { S2N_ERROR(S2N_ERR_SAFETY); } } while(0)
#define inclusive_range_check( low, n, high )   \
  do  {                                         \
    __typeof( n ) __tmp_n = ( n );              \
    gte_check(__tmp_n, low);                    \
    lte_check(__tmp_n, high);                   \
  } while (0)
#define exclusive_range_check( low, n, high )   \
  do {                                          \
    __typeof( n ) __tmp_n = ( n );              \
    gt_check(__tmp_n, low);                     \
    lt_check(__tmp_n, high);                    \
  } while (0)

#define GUARD( x )              do {if ( (x) < 0 ) return S2N_FAILURE;} while (0)
#define GUARD_GOTO( x , label ) do {if ( (x) < 0 ) goto label;} while (0)
#define GUARD_PTR( x )          do {if ( (x) < 0 ) return NULL;} while (0)

#define GUARD_NONNULL( x )              do {if ( (x) == NULL ) return S2N_FAILURE;} while (0)
#define GUARD_NONNULL_GOTO( x , label ) do {if ( (x) == NULL ) goto label;} while (0)
#define GUARD_NONNULL_PTR( x )          do {if ( (x) == NULL ) return NULL;} while (0)

/* Check the return value from caller. If this value is -2, S2N_ERR_BLOCKED is marked*/
#define GUARD_AGAIN( x )  do {if ( (x) == -2 ) { S2N_ERROR(S2N_ERR_BLOCKED); } GUARD( x );} while(0)

/* Returns true if s2n is in unit test mode, false otherwise */
bool s2n_in_unit_test();

/* Sets whether s2n is in unit test mode */
int s2n_in_unit_test_set(bool newval);

#define S2N_IN_INTEG_TEST ( getenv("S2N_INTEG_TEST") != NULL )
#define S2N_IN_TEST ( s2n_in_unit_test() || S2N_IN_INTEG_TEST )

/* TODO: use the OSSL error code in error reporting https://github.com/awslabs/s2n/issues/705 */
#define GUARD_OSSL( x , errcode )               \
  do {                                          \
  if (( x ) != 1) {                             \
    S2N_ERROR( errcode );                       \
  }                                             \
  } while (0)

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

/* Runs _thecleanup function on _thealloc once _thealloc went out of scope */
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

#define s2n_array_len(array) (sizeof(array) / sizeof(array[0]))

extern int s2n_mul_overflow(uint32_t a, uint32_t b, uint32_t* out);
