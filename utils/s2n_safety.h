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

#define TO_STRING(s) #s
#define STRING_(s) TO_STRING(s)
#define STRING__LINE__ STRING_(__LINE__)

/* NULL check a pointer */
#define notnull_check( ptr )           do { if ( (ptr) == NULL ) { *err = "NULL pointer encountered in " __FILE__ " line " STRING__LINE__; return -1; } } while(0)

/* Check memcpy's return, if it's not right (very unlikely!) bail, set an error
 * err and return -1;
 */
#define memcpy_check( d, s, n )     do { notnull_check( (d) ); if ( memcpy( (d), (s), (n)) != (d) ) { *err = "memcpy error in " __FILE__ " line " STRING__LINE__; return -1; } } while(0)
#define memset_check( d, c, n )     do { notnull_check( (d) ); if ( memset( (d), (c), (n)) != (d) ) { *err = "memset error in " __FILE__ " line " STRING__LINE__; return -1; } } while(0)

/* Range check a number */
#define gte_check(n, min)  do { if ( (n) < min ) { *err = "value is too low in " __FILE__ " line " STRING__LINE__; return -1; } } while(0)
#define lte_check(n, max)  do { if ( (n) > max ) { *err = "value is too high in " __FILE__ " line " STRING__LINE__; return -1; } } while(0)
#define gt_check(n, min)  do { if ( (n) <= min ) { *err = "value is too low in " __FILE__ " line " STRING__LINE__; return -1; } } while(0)
#define lt_check(n, max)  do { if ( (n) >= max ) { *err = "value is too high in " __FILE__ " line " STRING__LINE__; return -1; } } while(0)
#define eq_check(a, b)  do { if ( (a) != (b) ) { *err = "values mismatch in " __FILE__ " line " STRING__LINE__; return -1; } } while(0)
#define ne_check(a, b)  do { if ( (a) == (b) ) { *err = "values match in " __FILE__ " line " STRING__LINE__; return -1; } } while(0)
#define inclusive_range_check( low, n, high )  gte_check(n, low); lte_check(n, high)
#define exclusive_range_check( low, n, high )  gt_check(n, low); lt_check(n, high)

#define GUARD( x )      if ( (x) < 0 ) return -1
#define GUARD_REASON( x, y )   do { if ( (x) < 0 ) { *err = (y) ; return -1 } } while(0)

/**
 * Get the process id
 *
 * Returns:
 *  The process ID of the current process
 */
extern pid_t s2n_actual_getpid();

/* Returns 1 if a and b are equal, in constant time */
extern int s2n_constant_time_equals(const uint8_t *a, const uint8_t *b, uint32_t len);
