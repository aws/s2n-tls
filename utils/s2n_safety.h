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

#define GUARD( x )              if ( (x) < 0 ) return -1
#define GUARD_GOTO( x , label ) if ( (x) < 0 ) goto label
#define GUARD_PTR( x )          if ( (x) < 0 ) return NULL

/* TODO: use the OSSL error code in error reporting https://github.com/awslabs/s2n/issues/705 */
#define GUARD_OSSL( x , errcode )			\
  do {							\
  if (( x ) != 1) {					\
    S2N_ERROR( errcode );				\
  }							\
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
extern int s2n_constant_time_copy_or_dont(const uint8_t * dst, const uint8_t * src, uint32_t len, uint8_t dont);
