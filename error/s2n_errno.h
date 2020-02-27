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

#include <s2n.h>
#include <stdio.h>
#include <stdbool.h>

#define S2N_DEBUG_STR_LEN 128
extern __thread const char *s2n_debug_str;

#define TO_STRING(s) #s
#define STRING_(s) TO_STRING(s)
#define STRING__LINE__ STRING_(__LINE__)

#define _S2N_DEBUG_LINE     "Error encountered in " __FILE__ " line " STRING__LINE__
#define _S2N_ERROR( x )     do { s2n_debug_str = _S2N_DEBUG_LINE; s2n_errno = ( x ); s2n_calculate_stacktrace(); } while (0)
#define S2N_ERROR( x )      do { _S2N_ERROR( ( x ) ); return -1; } while (0)
#define S2N_ERROR_PRESERVE_ERRNO() do { return -1; } while (0)
#define S2N_ERROR_PTR( x )  do { _S2N_ERROR( ( x ) ); return NULL; } while (0)
#define S2N_ERROR_IF( cond , x ) do { if ( cond ) { S2N_ERROR( x ); }} while (0)
#define S2N_ERROR_IF_PTR( cond , x ) do { if ( cond ) { S2N_ERROR_PTR( x ); }} while (0)

#ifdef __TIMING_CONTRACTS__
#    define S2N_PRECONDITION( cond ) (void) 0
#    define S2N_PRECONDITION_PTR( cond ) (void) 0
#else
#    define S2N_PRECONDITION( cond ) S2N_ERROR_IF(!(cond), S2N_ERR_PRECONDITION_VIOLATION)
#    define S2N_PRECONDITION_PTR( cond ) S2N_ERROR_IF_PTR(!(cond), S2N_ERR_PRECONDITION_VIOLATION)
#endif /* __TIMING_CONTRACTS__ */

/**
 * Define function contracts.
 * When the code is being verified using CBMC these contracts are formally verified;
 * When the code is built in debug mode, they are checked as much as possible using assertions
 * When the code is built in production mode, non-fatal contracts are not checked.
 * Violations of the function contracts are undefined behaviour.
 */
#ifdef CBMC
#    define S2N_MEM_IS_READABLE(base, len) __CPROVER_r_ok((base), (len))
#    define S2N_MEM_IS_WRITABLE(base, len) __CPROVER_w_ok((base), (len))
#else
/* the C runtime does not give a way to check these properties,
 * but we can at least check that the pointer is valid */
#    define S2N_MEM_IS_READABLE(base, len) (((len) == 0) || (base))
#    define S2N_MEM_IS_WRITABLE(base, len) (((len) == 0) || (base))
#endif /* CBMC */

#define S2N_OBJECT_PTR_IS_READABLE(ptr) S2N_MEM_IS_READABLE((ptr), sizeof(*(ptr)))
#define S2N_OBJECT_PTR_IS_WRITABLE(ptr) S2N_MEM_IS_WRITABLE((ptr), sizeof(*(ptr)))

/** Calculate and print stacktraces */
struct s2n_stacktrace {
  char **trace;
  int trace_size;
};

extern bool s2n_stack_traces_enabled();
extern int s2n_stack_traces_enabled_set(bool newval);

extern int s2n_calculate_stacktrace(void);
extern int s2n_print_stacktrace(FILE *fptr);
extern int s2n_free_stacktrace(void);
extern int s2n_get_stacktrace(struct s2n_stacktrace *trace);
