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

#include "s2n_annotations.h"
#include "sidetrail.h"

void __VERIFIER_assume(int);

#define MEMCOPY_COST 2
void *memcpy(void *str1, const void *str2, size_t n);

void *s2n_sidetrail_memset(void * ptr, int value, size_t num);

#define __S2N_ENSURE( cond, action )                       __VERIFIER_assume((cond))

#define __S2N_ENSURE_SAFE_MEMCPY( d , s , n , guard )      do { memcpy((d), (s), (n)); } while(0)

#define __S2N_ENSURE_SAFE_MEMSET( d , c , n , guard )      \
  do {                                                     \
    __typeof( n ) __tmp_n = ( n );                         \
    if ( __tmp_n ) {                                       \
      __typeof( d ) __tmp_d = ( d );                       \
      guard( __tmp_d );                                    \
      s2n_sidetrail_memset( __tmp_d, (c), __tmp_n);        \
    }                                                      \
  } while(0)
