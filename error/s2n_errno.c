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

#include <errno.h>
#include <strings.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <execinfo.h>
#include "error/s2n_errno.h"

#include <s2n.h>
#include "utils/s2n_map.h"
#include "utils/s2n_safety.h"

__thread int s2n_errno;
__thread const char *s2n_debug_str;

static const char *no_such_language = "Language is not supported for error translation";
static const char *no_such_error = "Internal s2n error";

/* Category macro for ALL_ERROR_TYPES for following switch cases */
#define ERR_SWITCH_CATEGORY(category, ENTRY, HEADER_ENTRY) \
    category##_ENTRIES(ENTRY, HEADER_ENTRY, category)

/* Define the entry macros for str errors */
#define ERR_STR_CASE(ERR, str) case ERR: return str;
#define ERR_STR_HEADER_CASE(ERR, str, cat) ERR_STR_CASE(ERR, str)

const char *s2n_strerror(int error, const char *lang)
{
    if (lang == NULL) {
        lang = "EN";
    }

    if (strcasecmp(lang, "EN")) {
        return no_such_language;
    }

    s2n_error err = error;
    switch (err) {
        /* the lengthy switch case is expand from the following macros */
        ALL_ERROR_TYPES(ERR_SWITCH_CATEGORY, ERR_STR_CASE, ERR_STR_HEADER_CASE)

        /* Skip block ends */
        case S2N_ERR_T_OK_END:
        case S2N_ERR_T_IO_END:
        case S2N_ERR_T_CLOSED_END:
        case S2N_ERR_T_BLOCKED_END:
        case S2N_ERR_T_ALERT_END:
        case S2N_ERR_T_PROTO_END:
        case S2N_ERR_T_INTERNAL_END:
        case S2N_ERR_T_USAGE_END:
            break;

        /* No default to make compiler fail on missing values */
    }

    return no_such_error;
}

/* Define the entry macros for error type lookups */
#define ERR_NAME_CASE(ERR, str) case ERR: return #ERR;
#define ERR_NAME_HEADER_CASE(ERR, str, cat) ERR_NAME_CASE(ERR, str)

const char *s2n_strerror_name(int error)
{
    s2n_error err = error;
    switch (err) {
        /* the lengthy switch case is expand from the following macros */
        ALL_ERROR_TYPES(ERR_SWITCH_CATEGORY, ERR_NAME_CASE, ERR_NAME_HEADER_CASE)

        /* Skip block ends */
        case S2N_ERR_T_OK_END:
        case S2N_ERR_T_IO_END:
        case S2N_ERR_T_CLOSED_END:
        case S2N_ERR_T_BLOCKED_END:
        case S2N_ERR_T_ALERT_END:
        case S2N_ERR_T_PROTO_END:
        case S2N_ERR_T_INTERNAL_END:
        case S2N_ERR_T_USAGE_END:
            break;

        /* No default to make compiler fail on missing values */
    }

    return no_such_error;
}

const char *s2n_strerror_debug(int error, const char *lang)
{
    if (lang == NULL) {
        lang = "EN";
    }

    if (strcasecmp(lang, "EN")) {
        return no_such_language;
    }

    /* No error, just return the no error string */
    if (error == S2N_ERR_OK) {
        return s2n_strerror(error, lang);
    }

    return s2n_debug_str;
}

int s2n_error_get_type(int error)
{
    return (error >> S2N_ERR_NUM_VALUE_BITS);
}


/* https://www.gnu.org/software/libc/manual/html_node/Backtraces.html */
static bool s_s2n_stack_traces_enabled;

bool s2n_stack_traces_enabled()
{
    return s_s2n_stack_traces_enabled;
}

int s2n_stack_traces_enabled_set(bool newval)
{
    s_s2n_stack_traces_enabled = newval;
    return S2N_SUCCESS;
}

#define MAX_BACKTRACE_DEPTH 20
__thread struct s2n_stacktrace tl_stacktrace = {0};

int s2n_free_stacktrace(void)
{
    if (tl_stacktrace.trace != NULL) {
        free(tl_stacktrace.trace);
	struct s2n_stacktrace zero_stacktrace = {0};
	tl_stacktrace = zero_stacktrace;
    }
    return S2N_SUCCESS;
}

int s2n_calculate_stacktrace(void)
{
    if (!s_s2n_stack_traces_enabled) {
        return S2N_SUCCESS;
    }

    int old_errno = errno;
    GUARD(s2n_free_stacktrace());
    void *array[MAX_BACKTRACE_DEPTH];
    tl_stacktrace.trace_size = backtrace(array, MAX_BACKTRACE_DEPTH);
    tl_stacktrace.trace = backtrace_symbols(array, tl_stacktrace.trace_size);
    errno = old_errno;
    return S2N_SUCCESS;
}

int s2n_get_stacktrace(struct s2n_stacktrace *trace) {
    *trace = tl_stacktrace;
    return S2N_SUCCESS;
}

int s2n_print_stacktrace(FILE *fptr)
{
    if (!s_s2n_stack_traces_enabled) {
      fprintf(fptr, "%s\n%s\n",
	      "NOTE: Some details are omitted, run with S2N_PRINT_STACKTRACE=1 for a verbose backtrace.",
	      "See https://github.com/awslabs/s2n/blob/master/docs/USAGE-GUIDE.md");
        return S2N_SUCCESS;
    }

    fprintf(fptr, "\nStacktrace is:\n");
    for (int i = 0; i < tl_stacktrace.trace_size; ++i){
        fprintf(fptr, "%s\n",  tl_stacktrace.trace[i]);
    }
    return S2N_SUCCESS;
}
