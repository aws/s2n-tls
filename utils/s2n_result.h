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

#include <stdbool.h>

#include "api/s2n.h"

/* A value which indicates the outcome of a function */
typedef struct {
    int __error_signal;
} s2n_result;

/* used to signal a successful function return */
#define S2N_RESULT_OK ((s2n_result){ S2N_SUCCESS })

/* used to signal an error while executing a function */
#define S2N_RESULT_ERROR ((s2n_result){ S2N_FAILURE })

#if defined(__clang__) || defined(__GNUC__)
    #define S2N_RESULT_MUST_USE __attribute__((warn_unused_result))
#else
    #define S2N_RESULT_MUST_USE
#endif

/* returns true when the result is S2N_RESULT_OK */
S2N_RESULT_MUST_USE bool s2n_result_is_ok(s2n_result result);

/* returns true when the result is S2N_RESULT_ERROR */
S2N_RESULT_MUST_USE bool s2n_result_is_error(s2n_result result);

/**
 * Ignores the returned result of a function
 *
 * Generally, function results should always be checked. Using this function
 * could cause the system to behave in unexpected ways. As such, this function
 * should only be used in scenarios where the system state is not affected by
 * errors.
 */
void s2n_result_ignore(s2n_result result);

/* used in function declarations to signal function fallibility */
#define S2N_RESULT S2N_RESULT_MUST_USE s2n_result

/* The DEFER_CLEANUP macro discards the result of its cleanup function.
 * We need a version of s2n_result which can be ignored.
 */
#define S2N_CLEANUP_RESULT s2n_result
