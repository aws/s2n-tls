import textwrap

copyright = """
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
"""

header = copyright + """
#pragma once

/**
 * DO NOT DIRECTLY MODIFY THIS FILE:
 *
 * The code in this file is generated from scripts/s2n_safety_macros.py and any modifications
 * should be in there.
 */

/* clang-format off */

#include "error/s2n_errno.h"
#include "utils/s2n_ensure.h"
#include "utils/s2n_result.h"

/**
 * The goal of s2n_safety is to provide helpers to perform common
 * checks, which help with code readability.
 */

/* Success signal value for OpenSSL functions */
#define _OSSL_SUCCESS 1

"""

POSIX = dict(
    name = "POSIX",
    is_ok = "(result) > S2N_FAILURE",
    ok = "S2N_SUCCESS",
    error = "S2N_FAILURE",
    ret = "int",
    ret_doc = "`int` (POSIX error signal)",
    expect_ok = "EXPECT_SUCCESS",
    expect_err = "EXPECT_FAILURE_WITH_ERRNO",
)

PTR = dict(
    name = "PTR",
    is_ok = "(result) != NULL",
    ok = '"ok"',
    error = "NULL",
    ret = "const char*",
    ret_doc = "a pointer",
    expect_ok = "EXPECT_NOT_NULL",
    expect_err = "EXPECT_NULL_WITH_ERRNO",
)

RESULT = dict(
    name = "RESULT",
    is_ok = "s2n_result_is_ok(result)",
    ok = "S2N_RESULT_OK",
    error = "S2N_RESULT_ERROR",
    ret = "s2n_result",
    ret_doc = "`S2N_RESULT`",
    expect_ok = "EXPECT_OK",
    expect_err = "EXPECT_ERROR_WITH_ERRNO",
)

DEFAULT = dict(
    name = "",
    is_ok = RESULT['is_ok'],
    ok = RESULT['ok'],
    error = RESULT['error'],
    ret = RESULT['ret'],
    expect_ok = RESULT['expect_ok'],
    expect_err = RESULT['expect_err'],
)

# TODO add DEFAULT and remove RESULT once all PR branches are up-to-date
CONTEXTS = [RESULT, POSIX, PTR]

max_prefix_len = max(map(lambda c: len(c['name']), CONTEXTS))

def cmp_check(op):
    return '__S2N_ENSURE((a) ' + op + ' (b), {bail}(S2N_ERR_SAFETY))'

    ## TODO ensure type compatibility
    # return '''\\
    # do {{ \\
    #     static_assert(__builtin_types_compatible_p(__typeof(a), __typeof(b)), "types do not match"); \\
    #     __typeof(a) __tmp_a = ( a ); \\
    #     __typeof(b) __tmp_b = ( b ); \\
    #     __S2N_ENSURE(__tmp_a ''' + op + ''' __tmp_b, {bail}(S2N_ERR_SAFETY)); \\
    # }} while(0)
    # '''

MACROS = {
    'BAIL(error)': dict(
        doc  = 'Sets the global `s2n_errno` to `error` and returns with an `{error}`',
        impl = 'do {{ _S2N_ERROR((error)); __S2N_ENSURE_CHECKED_RETURN({error}); }} while (0)',
        harness = '''
        static {ret} {bail}_harness()
        {{
            {bail}(S2N_ERR_SAFETY);
            return {ok};
        }}
        ''',
        tests = [
            '{expect_err}({bail}_harness(), S2N_ERR_SAFETY);'
        ],
    ),
    'ENSURE(condition, error)': dict(
        doc  = 'Ensures the `condition` is `true`, otherwise the function will `{bail}` with `error`',
        impl = '__S2N_ENSURE((condition), {bail}(error))',
        harness = '''
        static {ret} {prefix}ENSURE_harness(bool is_ok)
        {{
            {prefix}ENSURE(is_ok, S2N_ERR_SAFETY);
            return {ok};
        }}
        ''',
        tests = [
            '{expect_ok}({prefix}ENSURE_harness(true));',
            '{expect_err}({prefix}ENSURE_harness(false), S2N_ERR_SAFETY);'
        ],
    ),
    'DEBUG_ENSURE(condition, error)': dict(
        doc  = '''
        Ensures the `condition` is `true`, otherwise the function will `{bail}` with `error`

        NOTE: The condition will _only_ be checked when the code is compiled in debug mode.
              In release mode, the check is removed.
        ''',
        impl = '__S2N_ENSURE_DEBUG((condition), {bail}(error))',
        harness = '''
        static {ret} {prefix}DEBUG_ENSURE_harness(bool is_ok)
        {{
            {prefix}DEBUG_ENSURE(is_ok, S2N_ERR_SAFETY);
            return {ok};
        }}
        ''',
        tests = [
            '{expect_ok}({prefix}DEBUG_ENSURE_harness(true));',
            '#ifdef NDEBUG',
            '{expect_ok}({prefix}DEBUG_ENSURE_harness(false));',
            '#else',
            '{expect_err}({prefix}DEBUG_ENSURE_harness(false), S2N_ERR_SAFETY);',
            '#endif',
        ],
    ),
    'ENSURE_OK(result, error)': dict(
        doc  = '''
        Ensures `{is_ok}`, otherwise the function will `{bail}` with `error`
        
        This can be useful for overriding the global `s2n_errno`
        ''',
        impl = '__S2N_ENSURE({is_ok}, {bail}(error))',
        harness = '''
        static {ret} {prefix}ENSURE_OK_harness(bool is_ok)
        {{
            {prefix}ENSURE_OK({prefix}ENSURE_harness(is_ok), S2N_ERR_IO);
            return {ok};
        }}
        ''',
        tests = [
            '{expect_ok}({prefix}ENSURE_OK_harness(true));',
            '{expect_err}({prefix}ENSURE_OK_harness(false), S2N_ERR_IO);'
        ],
    ),
    'ENSURE_GTE(a, b)': dict(
        doc  = '''
        Ensures `a` is greater than or equal to `b`, otherwise the function will `{bail}` with a `S2N_ERR_SAFETY` error
        ''',
        impl = cmp_check('>='),
        harness = '''
        static {ret} {prefix}ENSURE_GTE_harness_uint32(uint32_t a, uint32_t b)
        {{
            {prefix}ENSURE_GTE(a, b);
            /* test the inverse */
            {prefix}ENSURE_LTE(b, a);
            return {ok};
        }}

        static {ret} {prefix}ENSURE_GTE_harness_int32(int32_t a, int32_t b)
        {{
            {prefix}ENSURE_GTE(a, b);
            /* test the inverse */
            {prefix}ENSURE_LTE(b, a);
            return {ok};
        }}
        ''',
        tests = [
            '{expect_ok}({prefix}ENSURE_GTE_harness_uint32(0, 0));',
            '{expect_ok}({prefix}ENSURE_GTE_harness_uint32(1, 0));',
            '{expect_err}({prefix}ENSURE_GTE_harness_uint32(0, 1), S2N_ERR_SAFETY);',
            '{expect_ok}({prefix}ENSURE_GTE_harness_int32(-1, -2));',
            '{expect_ok}({prefix}ENSURE_GTE_harness_int32(-1, -1));',
            '{expect_err}({prefix}ENSURE_GTE_harness_int32(-2, -1), S2N_ERR_SAFETY);',
        ],
    ),
    'ENSURE_LTE(a, b)': dict(
        doc  = '''
        Ensures `a` is less than or equal to `b`, otherwise the function will `{bail}` with a `S2N_ERR_SAFETY` error
        ''',
        impl = cmp_check('<='),
        harness = '''
        static {ret} {prefix}ENSURE_LTE_harness_uint32(uint32_t a, uint32_t b)
        {{
            {prefix}ENSURE_LTE(a, b);
            /* test the inverse */
            {prefix}ENSURE_GTE(b, a);
            return {ok};
        }}

        static {ret} {prefix}ENSURE_LTE_harness_int32(int32_t a, int32_t b)
        {{
            {prefix}ENSURE_LTE(a, b);
            /* test the inverse */
            {prefix}ENSURE_GTE(b, a);
            return {ok};
        }}
        ''',
        tests = [
            '{expect_ok}({prefix}ENSURE_LTE_harness_uint32(0, 0));',
            '{expect_ok}({prefix}ENSURE_LTE_harness_uint32(0, 1));',
            '{expect_err}({prefix}ENSURE_LTE_harness_uint32(1, 0), S2N_ERR_SAFETY);',
            '{expect_ok}({prefix}ENSURE_LTE_harness_int32(-2, -1));',
            '{expect_ok}({prefix}ENSURE_LTE_harness_int32(-1, -1));',
            '{expect_err}({prefix}ENSURE_LTE_harness_int32(-1, -2), S2N_ERR_SAFETY);',
        ],
    ),
    'ENSURE_GT(a, b)': dict(
        doc  = '''
        Ensures `a` is greater than `b`, otherwise the function will `{bail}` with a `S2N_ERR_SAFETY` error
        ''',
        impl = cmp_check('>'),
        harness = '''
        static {ret} {prefix}ENSURE_GT_harness_uint32(uint32_t a, uint32_t b)
        {{
            {prefix}ENSURE_GT(a, b);
            /* test the inverse */
            {prefix}ENSURE_LT(b, a);
            return {ok};
        }}

        static {ret} {prefix}ENSURE_GT_harness_int32(int32_t a, int32_t b)
        {{
            {prefix}ENSURE_GT(a, b);
            /* test the inverse */
            {prefix}ENSURE_LT(b, a);
            return {ok};
        }}
        ''',
        tests = [
            '{expect_err}({prefix}ENSURE_GT_harness_uint32(0, 0), S2N_ERR_SAFETY);',
            '{expect_ok}({prefix}ENSURE_GT_harness_uint32(1, 0));',
            '{expect_err}({prefix}ENSURE_GT_harness_uint32(0, 1), S2N_ERR_SAFETY);',
            '{expect_ok}({prefix}ENSURE_GT_harness_int32(-1, -2));',
            '{expect_err}({prefix}ENSURE_GT_harness_int32(-1, -1), S2N_ERR_SAFETY);',
            '{expect_err}({prefix}ENSURE_GT_harness_int32(-2, -1), S2N_ERR_SAFETY);',
        ],
    ),
    'ENSURE_LT(a, b)': dict(
        doc  = '''
        Ensures `a` is less than `b`, otherwise the function will `{bail}` with a `S2N_ERR_SAFETY` error
        ''',
        impl = cmp_check('<'),
        harness = '''
        static {ret} {prefix}ENSURE_LT_harness_uint32(uint32_t a, uint32_t b)
        {{
            {prefix}ENSURE_LT(a, b);
            /* test the inverse */
            {prefix}ENSURE_GT(b, a);
            return {ok};
        }}

        static {ret} {prefix}ENSURE_LT_harness_int32(int32_t a, int32_t b)
        {{
            {prefix}ENSURE_LT(a, b);
            /* test the inverse */
            {prefix}ENSURE_GT(b, a);
            return {ok};
        }}
        ''',
        tests = [
            '{expect_err}({prefix}ENSURE_LT_harness_uint32(0, 0), S2N_ERR_SAFETY);',
            '{expect_ok}({prefix}ENSURE_LT_harness_uint32(0, 1));',
            '{expect_err}({prefix}ENSURE_LT_harness_uint32(1, 0), S2N_ERR_SAFETY);',
            '{expect_ok}({prefix}ENSURE_LT_harness_int32(-2, -1));',
            '{expect_err}({prefix}ENSURE_LT_harness_int32(-1, -1), S2N_ERR_SAFETY);',
            '{expect_err}({prefix}ENSURE_LT_harness_int32(-1, -2), S2N_ERR_SAFETY);',
        ],
    ),
    'ENSURE_EQ(a, b)': dict(
        doc  = '''
        Ensures `a` is equal to `b`, otherwise the function will `{bail}` with a `S2N_ERR_SAFETY` error
        ''',
        impl = cmp_check('=='),
        harness = '''
        static {ret} {prefix}ENSURE_EQ_harness_uint32(uint32_t a, uint32_t b)
        {{
            {prefix}ENSURE_EQ(a, b);
            {prefix}ENSURE_EQ(b, a);
            return {ok};
        }}

        static {ret} {prefix}ENSURE_EQ_harness_int32(int32_t a, int32_t b)
        {{
            {prefix}ENSURE_EQ(a, b);
            {prefix}ENSURE_EQ(b, a);
            return {ok};
        }}
        ''',
        tests = [
            '{expect_ok}({prefix}ENSURE_EQ_harness_uint32(0, 0));',
            '{expect_err}({prefix}ENSURE_EQ_harness_uint32(1, 0), S2N_ERR_SAFETY);',
            '{expect_ok}({prefix}ENSURE_EQ_harness_int32(-1, -1));',
            '{expect_err}({prefix}ENSURE_EQ_harness_int32(-2, -1), S2N_ERR_SAFETY);',
        ],
    ),
    'ENSURE_NE(a, b)': dict(
        doc  = '''
        Ensures `a` is not equal to `b`, otherwise the function will `{bail}` with a `S2N_ERR_SAFETY` error
        ''',
        impl = cmp_check('!='),
        harness = '''
        static {ret} {prefix}ENSURE_NE_harness_uint32(uint32_t a, uint32_t b)
        {{
            {prefix}ENSURE_NE(a, b);
            {prefix}ENSURE_NE(b, a);
            return {ok};
        }}

        static {ret} {prefix}ENSURE_NE_harness_int32(int32_t a, int32_t b)
        {{
            {prefix}ENSURE_NE(a, b);
            {prefix}ENSURE_NE(b, a);
            return {ok};
        }}
        ''',
        tests = [
            '{expect_ok}({prefix}ENSURE_NE_harness_uint32(1, 0));',
            '{expect_err}({prefix}ENSURE_NE_harness_uint32(0, 0), S2N_ERR_SAFETY);',
            '{expect_ok}({prefix}ENSURE_NE_harness_int32(-2, -1));',
            '{expect_err}({prefix}ENSURE_NE_harness_int32(-1, -1), S2N_ERR_SAFETY);',
        ],
    ),
    'ENSURE_INCLUSIVE_RANGE(min, n, max)': dict(
        doc  = 'Ensures `min <= n <= max`, otherwise the function will `{bail}` with `S2N_ERR_SAFETY`',
        impl = ''' \\
        do {{ \\
            __typeof(n) __tmp_n = ( n ); \\
            __typeof(n) __tmp_min = ( min ); \\
            __typeof(n) __tmp_max = ( max ); \\
            {prefix}ENSURE_GTE(__tmp_n, __tmp_min); \\
            {prefix}ENSURE_LTE(__tmp_n, __tmp_max); \\
        }} while(0)''',
        harness = '''
        static {ret} {prefix}ENSURE_INCLUSIVE_RANGE_harness_uint32(uint32_t a, uint32_t b, uint32_t c)
        {{
            {prefix}ENSURE_INCLUSIVE_RANGE(a, b, c);
            return {ok};
        }}

        static {ret} {prefix}ENSURE_INCLUSIVE_RANGE_harness_int32(int32_t a, int32_t b, int32_t c)
        {{
            {prefix}ENSURE_INCLUSIVE_RANGE(a, b, c);
            return {ok};
        }}
        ''',
        tests = [
            '{expect_err}({prefix}ENSURE_INCLUSIVE_RANGE_harness_uint32(1, 0, 2), S2N_ERR_SAFETY);',
            '{expect_ok}({prefix}ENSURE_INCLUSIVE_RANGE_harness_uint32(1, 1, 2));',
            '{expect_ok}({prefix}ENSURE_INCLUSIVE_RANGE_harness_uint32(1, 2, 2));',
            '{expect_err}({prefix}ENSURE_INCLUSIVE_RANGE_harness_uint32(1, 3, 2), S2N_ERR_SAFETY);',

            '{expect_err}({prefix}ENSURE_INCLUSIVE_RANGE_harness_int32(-2, -3, -1), S2N_ERR_SAFETY);',
            '{expect_ok}({prefix}ENSURE_INCLUSIVE_RANGE_harness_int32(-2, -2, -1));',
            '{expect_ok}({prefix}ENSURE_INCLUSIVE_RANGE_harness_int32(-2, -1, -1));',
            '{expect_err}({prefix}ENSURE_INCLUSIVE_RANGE_harness_int32(-2, 0, -1), S2N_ERR_SAFETY);',
        ],
    ),
    'ENSURE_EXCLUSIVE_RANGE(min, n, max)': dict(
        doc  = 'Ensures `min < n < max`, otherwise the function will `{bail}` with `S2N_ERR_SAFETY`',
        impl = ''' \\
        do {{ \\
            __typeof(n) __tmp_n = ( n ); \\
            __typeof(n) __tmp_min = ( min ); \\
            __typeof(n) __tmp_max = ( max ); \\
            {prefix}ENSURE_GT(__tmp_n, __tmp_min); \\
            {prefix}ENSURE_LT(__tmp_n, __tmp_max); \\
        }} while(0)''',
        harness = '''
        static {ret} {prefix}ENSURE_EXCLUSIVE_RANGE_harness_uint32(uint32_t a, uint32_t b, uint32_t c)
        {{
            {prefix}ENSURE_EXCLUSIVE_RANGE(a, b, c);
            return {ok};
        }}

        static {ret} {prefix}ENSURE_EXCLUSIVE_RANGE_harness_int32(int32_t a, int32_t b, int32_t c)
        {{
            {prefix}ENSURE_EXCLUSIVE_RANGE(a, b, c);
            return {ok};
        }}
        ''',
        tests = [
            '{expect_err}({prefix}ENSURE_EXCLUSIVE_RANGE_harness_uint32(1, 0, 3), S2N_ERR_SAFETY);',
            '{expect_err}({prefix}ENSURE_EXCLUSIVE_RANGE_harness_uint32(1, 1, 3), S2N_ERR_SAFETY);',
            '{expect_ok}({prefix}ENSURE_EXCLUSIVE_RANGE_harness_uint32(1, 2, 3));',
            '{expect_err}({prefix}ENSURE_EXCLUSIVE_RANGE_harness_uint32(1, 3, 3), S2N_ERR_SAFETY);',
            '{expect_err}({prefix}ENSURE_EXCLUSIVE_RANGE_harness_uint32(1, 4, 3), S2N_ERR_SAFETY);',

            '{expect_err}({prefix}ENSURE_EXCLUSIVE_RANGE_harness_int32(-3, -4, -1), S2N_ERR_SAFETY);',
            '{expect_err}({prefix}ENSURE_EXCLUSIVE_RANGE_harness_int32(-3, -3, -1), S2N_ERR_SAFETY);',
            '{expect_ok}({prefix}ENSURE_EXCLUSIVE_RANGE_harness_int32(-3, -2, -1));',
            '{expect_err}({prefix}ENSURE_EXCLUSIVE_RANGE_harness_int32(-3, -1, -1), S2N_ERR_SAFETY);',
            '{expect_err}({prefix}ENSURE_EXCLUSIVE_RANGE_harness_int32(-3, 0, -1), S2N_ERR_SAFETY);',
        ],
    ),
    'ENSURE_REF(x)': dict(
        doc  = 'Ensures `x` is a readable reference, otherwise the function will `{bail}` with `S2N_ERR_NULL`',
        impl = '__S2N_ENSURE(S2N_OBJECT_PTR_IS_READABLE(x), {bail}(S2N_ERR_NULL))',
        harness = '''
        static {ret} {prefix}ENSURE_REF_harness(const char* str)
        {{
            {prefix}ENSURE_REF(str);
            return {ok};
        }}
        ''',
        tests = [
            '{expect_ok}({prefix}ENSURE_REF_harness(""));',
            '{expect_ok}({prefix}ENSURE_REF_harness("ok"));',
            '{expect_err}({prefix}ENSURE_REF_harness(NULL), S2N_ERR_NULL);',
        ],
    ),
    'ENSURE_MUT(x)': dict(
        doc  = 'Ensures `x` is a mutable reference, otherwise the function will `{bail}` with `S2N_ERR_NULL`',
        impl = '__S2N_ENSURE(S2N_OBJECT_PTR_IS_WRITABLE(x), {bail}(S2N_ERR_NULL))',
        harness = '''
        static {ret} {prefix}ENSURE_MUT_harness(uint32_t* v)
        {{
            {prefix}ENSURE_MUT(v);
            return {ok};
        }}
        ''',
        tests = [
            'uint32_t {prefix}ensure_mut_test = 0;',
            '{expect_ok}({prefix}ENSURE_MUT_harness(&{prefix}ensure_mut_test));',
            '{prefix}ensure_mut_test = 1;',
            '{expect_ok}({prefix}ENSURE_MUT_harness(&{prefix}ensure_mut_test));',
            '{expect_err}({prefix}ENSURE_MUT_harness(NULL), S2N_ERR_NULL);',
        ],
    ),
    'PRECONDITION(result)': dict(
        doc  = '''
        Ensures the `result` is `S2N_RESULT_OK`, otherwise the function will return an error signal

        `{prefix}PRECONDITION` should be used at the beginning of a function to make assertions about
        the provided arguments. By default, it is functionally equivalent to `{prefix}GUARD_RESULT(result)`
        but can be altered by a testing environment to provide additional guarantees.
        ''',
        impl = '{prefix}GUARD_RESULT(__S2N_ENSURE_PRECONDITION((result)))',
        harness = '''
        static S2N_RESULT {prefix}PRECONDITION_harness_check(bool is_ok)
        {{
            RESULT_ENSURE(is_ok, S2N_ERR_SAFETY);
            return S2N_RESULT_OK;
        }}

        static {ret} {prefix}PRECONDITION_harness(s2n_result result)
        {{
            {prefix}PRECONDITION(result);
            return {ok};
        }}
        ''',
        tests = [
            '{expect_ok}({prefix}PRECONDITION_harness({prefix}PRECONDITION_harness_check(true)));',
            '{expect_err}({prefix}PRECONDITION_harness({prefix}PRECONDITION_harness_check(false)), S2N_ERR_SAFETY);',
        ],
    ),
    'POSTCONDITION(result)': dict(
        doc  = '''
        Ensures the `result` is `S2N_RESULT_OK`, otherwise the function will return an error signal

        NOTE: The condition will _only_ be checked when the code is compiled in debug mode.
              In release mode, the check is removed.

        `{prefix}POSTCONDITION` should be used at the end of a function to make assertions about
        the resulting state. In debug mode, it is functionally equivalent to `{prefix}GUARD_RESULT(result)`.
        In production builds, it becomes a no-op. This can also be altered by a testing environment
        to provide additional guarantees.
        ''',
        impl = '{prefix}GUARD_RESULT(__S2N_ENSURE_POSTCONDITION((result)))',
        harness = '''
        static S2N_RESULT {prefix}POSTCONDITION_harness_check(bool is_ok)
        {{
            RESULT_ENSURE(is_ok, S2N_ERR_SAFETY);
            return S2N_RESULT_OK;
        }}

        static {ret} {prefix}POSTCONDITION_harness(s2n_result result)
        {{
            {prefix}POSTCONDITION(result);
            return {ok};
        }}
        ''',
        tests = [
            '{expect_ok}({prefix}POSTCONDITION_harness({prefix}POSTCONDITION_harness_check(true)));',
            '#ifdef NDEBUG',
            '{expect_ok}({prefix}POSTCONDITION_harness({prefix}POSTCONDITION_harness_check(false)));',
            '#else',
            '{expect_err}({prefix}POSTCONDITION_harness({prefix}POSTCONDITION_harness_check(false)), S2N_ERR_SAFETY);',
            '#endif',
        ],
    ),
    'CHECKED_MEMCPY(destination, source, len)': dict(
        doc  = '''
        Performs a safer memcpy.

        The following checks are performed:

        * `destination` is non-null
        * `source` is non-null

        Callers will still need to ensure the following:

        * The size of the data pointed to by both the `destination` and `source` parameters,
          shall be at least `len` bytes.
        ''',
        impl = '__S2N_ENSURE_SAFE_MEMCPY((destination), (source), (len), {prefix}GUARD_PTR)',
        harness = '''
        static {ret} {prefix}CHECKED_MEMCPY_harness(uint32_t* dest, uint32_t* source, size_t len)
        {{
            {prefix}CHECKED_MEMCPY(dest, source, len);
            return {ok};
        }}
        ''',
        tests = [
            'uint32_t {prefix}_checked_memcpy_dest = 1;',
            'uint32_t {prefix}_checked_memcpy_source = 2;',
            '{expect_ok}({prefix}CHECKED_MEMCPY_harness(&{prefix}_checked_memcpy_dest, &{prefix}_checked_memcpy_source, 0));',
            'EXPECT_EQUAL({prefix}_checked_memcpy_dest, 1);',
            '{expect_err}({prefix}CHECKED_MEMCPY_harness(NULL, &{prefix}_checked_memcpy_source, 4), S2N_ERR_NULL);',
            '{expect_err}({prefix}CHECKED_MEMCPY_harness(&{prefix}_checked_memcpy_dest, NULL, 4), S2N_ERR_NULL);',
            '{expect_ok}({prefix}CHECKED_MEMCPY_harness(&{prefix}_checked_memcpy_dest, &{prefix}_checked_memcpy_source, 4));',
            'EXPECT_EQUAL({prefix}_checked_memcpy_dest, {prefix}_checked_memcpy_source);'
        ],
    ),
    'CHECKED_MEMSET(destination, value, len)': dict(
        doc  = '''
        Performs a safer memset

        The following checks are performed:

        * `destination` is non-null

        Callers will still need to ensure the following:

        * The size of the data pointed to by the `destination` parameter shall be at least
          `len` bytes.
        ''',
        impl = '__S2N_ENSURE_SAFE_MEMSET((destination), (value), (len), {prefix}ENSURE_REF)',
        harness = '''
        static {ret} {prefix}CHECKED_MEMSET_harness(uint32_t* dest, uint8_t value, size_t len)
        {{
            {prefix}CHECKED_MEMSET(dest, value, len);
            return {ok};
        }}
        ''',
        tests = [
            'uint32_t {prefix}_checked_memset_dest = 1;',
            '{expect_ok}({prefix}CHECKED_MEMSET_harness(&{prefix}_checked_memset_dest, 0x42, 0));',
            'EXPECT_EQUAL({prefix}_checked_memset_dest, 1);',
            '{expect_err}({prefix}CHECKED_MEMSET_harness(NULL, 0x42, 1), S2N_ERR_NULL);',
            '{expect_ok}({prefix}CHECKED_MEMSET_harness(&{prefix}_checked_memset_dest, 0x42, 4));',
            'EXPECT_EQUAL({prefix}_checked_memset_dest, 0x42424242);'
        ],
    ),
    'GUARD(result)': dict(
        doc  = 'Ensures `{is_ok}`, otherwise the function will return `{error}`',
        impl = '__S2N_ENSURE({is_ok}, __S2N_ENSURE_CHECKED_RETURN({error}))',
        harness = '''
        static {ret} {prefix}GUARD_harness({ret} result)
        {{
            {prefix}GUARD(result);
            return {ok};
        }}
        ''',
        tests = [
            '{expect_ok}({prefix}GUARD_harness({prefix}ENSURE_harness(true)));',
            '{expect_err}({prefix}GUARD_harness({prefix}ENSURE_harness(false)), S2N_ERR_SAFETY);',
        ],
    ),
    'GUARD_OSSL(result, error)': dict(
        doc  = 'Ensures `result == _OSSL_SUCCESS`, otherwise the function will `{bail}` with `error`',
        impl = '__S2N_ENSURE((result) == _OSSL_SUCCESS, {bail}(error))',
        harness = '''
        static {ret} {prefix}GUARD_OSSL_harness(int result, int error)
        {{
            {prefix}GUARD_OSSL(result, error);
            return {ok};
        }}
        ''',
        tests = [
            '{expect_ok}({prefix}GUARD_OSSL_harness(1, S2N_ERR_SAFETY));',
            '{expect_err}({prefix}GUARD_OSSL_harness(0, S2N_ERR_SAFETY), S2N_ERR_SAFETY);',
        ],
    ),
}

max_macro_len = max(map(len, MACROS.keys())) + 8

def push_macro(args):
    macro_indent = ' ' * (max_macro_len - len(args['macro']))

    h = ""
    h += '/**\n'

    for line in args['doc'].split('\n'):
        h += ' *'
        if len(line) > 0:
            h += ' ' + line
        h += '\n'

    h += ' */\n'
    h += '#define '
    h += args['prefix']
    h += args['macro']
    h += args['indent']
    h += macro_indent
    h += args['impl'].format_map(args)
    h += '\n\n'

    return h

for context in CONTEXTS:
    # initialize contexts
    if len(context['name']) > 0:
        context['prefix'] = context['name'] + '_'
        context['suffix'] = '_' + context['name']
    else:
        context['prefix'] = ''
        context['suffix'] = ''

    context['indent'] = ' ' * (max_prefix_len - len(context['prefix']))
    context['bail'] = '{prefix}BAIL'.format_map(context)

harnesses = ""
docs = """
[//]: # (DO NOT DIRECTLY MODIFY THIS FILE:)
[//]: # (The code in this file is generated from scripts/s2n_safety_macros.py and any modifications)
[//]: # (should be in there.)

# S2N Safety Macros
"""
checks = []
deprecation_message = "DEPRECATED: all methods (except those in s2n.h) should return s2n_result."

def push_doc(args):
    args['doc'] = textwrap.dedent(args['doc']).format_map(args).strip()

    return textwrap.dedent("""
    ### {prefix}{macro}

    {doc}

    """).format_map(args)

for context in CONTEXTS:
    docs += textwrap.dedent("""
    ## Macros for functions that return {ret_doc}

    """).format_map(context)

    for name, value in MACROS.items():
        args = {'macro': name}
        args.update(context)
        args.update(value)

        args['doc'] = textwrap.dedent(args['doc']).strip()
        if context['ret'] != DEFAULT['ret']:
            args['doc'] = (deprecation_message + "\n\n" + args['doc'])

        docs += push_doc(args)
        header += push_macro(args)

        harness = value.get('harness', None)
        if harness != None:
            harnesses += textwrap.dedent(harness).format_map(context)
            checks.append('/* ' + context['prefix'] + name + ' */')
            assert len(value['tests']) > 0, "{} is missing tests".format(name)
            for check in value['tests']:
                checks.append(check.format_map(context))
            checks.append('')

    for other in CONTEXTS:
        if len(other['suffix']) > 0:
            doc = 'Ensures `{is_ok}`, otherwise the function will return `{error}`'
            if other == PTR:
                doc += '\n\nDoes not set s2n_errno to S2N_ERR_NULL, so is NOT a direct replacement for {prefix}ENSURE_REF.'
            if context['ret'] != DEFAULT['ret']:
                doc = (deprecation_message + "\n\n" + doc)

            if other == context:
                continue;

            impl = '__S2N_ENSURE({is_ok}, __S2N_ENSURE_CHECKED_RETURN({error}))'
            args = {
                'prefix': context['prefix'],
                'suffix': other['suffix'],
                'is_ok': other['is_ok'],
                'ok': other['ok'],
                'error': context['error'],
                'indent': context['indent'],
                'doc': doc,
                'impl': impl,
            }
            args['macro'] = 'GUARD{suffix}(result)'.format_map(args)
            docs += push_doc(args)
            header += push_macro(args)

def cleanup(contents):
    # Remove any unnecessary generated "X_GUARD_X"s, like "RESULT_GUARD_RESULT"
    for context in CONTEXTS:
        x_guard = "{name}_GUARD".format_map(context)
        x_guard_x = "{name}_GUARD_{name}".format_map(context)
        contents = contents.replace(x_guard_x, x_guard)
    return contents

def write(f, contents):
    contents = cleanup(contents)
    with open(f, "w") as header_file:
        header_file.write(contents)

write("utils/s2n_safety_macros.h", header)

test = copyright + '''
/* clang-format off */

#include "s2n_test.h"

#include "utils/s2n_safety.h"

/**
 * DO NOT DIRECTLY MODIFY THIS FILE:
 *
 * The code in this file is generated from scripts/s2n_safety_macros.py and any modifications
 * should be in there.
 */

/* harnesses */
'''
test += harnesses
test += '''
int main(int argc, char **argv)
{
    BEGIN_TEST();

'''
for check in checks:
    if len(check) > 0:
        test += '    ' + check
    test += '\n'

test += '''
    END_TEST();
    return S2N_SUCCESS;
}
'''

write("tests/unit/s2n_safety_macros_test.c", test)

write("docs/SAFETY-MACROS.md", docs)

