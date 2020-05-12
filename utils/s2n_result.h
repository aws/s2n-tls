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
#include <stdbool.h>

/* A value which indicates the outcome of a function */
typedef struct {
    int __error_signal;
} s2n_result;

/* used to signal a successful function return */
extern const s2n_result S2N_RESULT_OK;
/* used to signal an error while executing a function */
extern const s2n_result S2N_RESULT_ERROR;

#if defined(__clang__) || defined(__GNUC__)
#define S2N_RESULT_MUST_USE __attribute__((warn_unused_result))
#else
#define S2N_RESULT_MUST_USE
#endif

/* returns true when the result is S2N_RESULT_OK */
S2N_RESULT_MUST_USE bool s2n_result_is_ok(s2n_result result);

/* returns true when the result is S2N_RESULT_ERROR */
S2N_RESULT_MUST_USE bool s2n_result_is_error(s2n_result result);

/* used in function declarations to signal function fallibility */
#define S2N_RESULT S2N_RESULT_MUST_USE s2n_result

/* s2n_result GUARD helpers */
/* note: eventually this will just alias GUARD and be deprecated once everything is using s2n_result */
#define GUARD_RESULT( x )               do {if ( s2n_result_is_error(x) ) return S2N_RESULT_ERROR;} while (0)
#define GUARD_AS_RESULT( x )            do {if ( (x) < 0 ) return S2N_RESULT_ERROR;} while (0)
#define GUARD_AS_POSIX( x )             do {if ( s2n_result_is_error(x) ) return S2N_FAILURE;} while (0)
#define GUARD_RESULT_GOTO( x, label )   do {if ( s2n_result_is_error(x) ) goto label;} while (0)
#define GUARD_RESULT_PTR( x )           do {if ( s2n_result_is_error(x) ) return NULL;} while (0)

/* s2n_result ERROR helpers */
/* note: eventually this will just alias S2N_ERROR and be deprecated once everything is using s2n_result */
#define S2N_ERROR_RESULT( x )      do { _S2N_ERROR( ( x ) ); return S2N_RESULT_ERROR; } while (0)
#define S2N_ERROR_RESULT_PRESERVE_ERRNO() do { return S2N_RESULT_ERROR; } while (0)
#define S2N_ERROR_RESULT_PTR( x )  do { _S2N_ERROR( ( x ) ); return NULL; } while (0)
#define S2N_ERROR_RESULT_IF( cond , x ) do { if ( cond ) { S2N_ERROR_RESULT( x ); }} while (0)
