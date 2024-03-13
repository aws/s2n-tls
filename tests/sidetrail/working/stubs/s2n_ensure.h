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

#include "utils/s2n_annotations.h"
#include "sidetrail.h"

void __VERIFIER_assume(int);

#define MEMCOPY_COST 2
void *memcpy(void *str1, const void *str2, size_t n);

void *s2n_sidetrail_memset(void * ptr, int value, size_t num);

#define __S2N_ENSURE( cond, action )                       __VERIFIER_assume((cond))
#define __S2N_ENSURE_DEBUG( cond, action )                 __VERIFIER_assume((cond))

#define __S2N_ENSURE_PRECONDITION( result )                S2N_RESULT_OK
#define __S2N_ENSURE_POSTCONDITION( result )               S2N_RESULT_OK

/* memmove isn't supported, so use memcpy instead.
 * For the purposes of these proofs, there should be no useful difference.
 */
#define __S2N_ENSURE_SAFE_MEMMOVE( d , s , n , guard )      do { memcpy((d), (s), (n)); } while(0)

#define __S2N_ENSURE_SAFE_MEMSET( d , c , n , guard )      \
  do {                                                     \
    __typeof( n ) __tmp_n = ( n );                         \
    if ( __tmp_n ) {                                       \
      __typeof( d ) __tmp_d = ( d );                       \
      guard( __tmp_d );                                    \
      s2n_sidetrail_memset( __tmp_d, (c), __tmp_n);        \
    }                                                      \
  } while(0)

#define __S2N_ENSURE_CHECKED_RETURN(v)                     do { return v; } while(0)

/**
 * The C runtime does not give a way to check these properties,
 * but we can at least check for nullness.
 */
#define S2N_MEM_IS_READABLE_CHECK(base, len) (((len) == 0) || (base) != NULL)
#define S2N_MEM_IS_WRITABLE_CHECK(base, len) (((len) == 0) || (base) != NULL)

/**
 * These macros can safely be used in validate functions.
 */
#define S2N_MEM_IS_READABLE(base, len) (((len) == 0) || (base) != NULL)
#define S2N_MEM_IS_WRITABLE(base, len) (((len) == 0) || (base) != NULL)
#define S2N_OBJECT_PTR_IS_READABLE(ptr) ((ptr) != NULL)
#define S2N_OBJECT_PTR_IS_WRITABLE(ptr) ((ptr) != NULL)

#define S2N_IMPLIES(a, b) (!(a) || (b))
#define S2N_IFF(a, b) (!!(a) == !!(b))

/**
 * These macros are used to specify code contracts in CBMC proofs.
 */
#define CONTRACT_ASSIGNS(...)
#define CONTRACT_ASSIGNS_ERR(...)
#define CONTRACT_REQUIRES(...)
#define CONTRACT_ENSURES(...)
#define CONTRACT_INVARIANT(...)
#define CONTRACT_RETURN_VALUE
