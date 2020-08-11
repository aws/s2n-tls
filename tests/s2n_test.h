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
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/crypto.h>

#include "error/s2n_errno.h"
#include "utils/s2n_safety.h"
#include "utils/s2n_result.h"

int test_count;

/* Macro definitions for calls that occur within BEGIN_TEST() and END_TEST() to preserve the SKIPPED test behavior
 * by ignoring the test_count, keeping it as 0 to indicate that a test was skipped. */
#define EXPECT_TRUE_WITHOUT_COUNT( condition )    do { if ( !(condition) ) { FAIL_MSG( #condition " is not true "); } } while(0)
#define EXPECT_FALSE_WITHOUT_COUNT( condition )   EXPECT_TRUE_WITHOUT_COUNT( !(condition) )

#define EXPECT_NOT_EQUAL_WITHOUT_COUNT( p1, p2 )  EXPECT_FALSE_WITHOUT_COUNT( (p1) == (p2) )

#define EXPECT_SUCCESS_WITHOUT_COUNT( function_call )  EXPECT_NOT_EQUAL_WITHOUT_COUNT( (function_call) ,  -1 )

/**
 * This is a very basic, but functional unit testing framework. All testing should
 * happen in main() and start with a BEGIN_TEST() and end with an END_TEST();
 */
#define BEGIN_TEST()                                           \
  do {                                                         \
    test_count = 0;                                            \
    EXPECT_SUCCESS_WITHOUT_COUNT(s2n_in_unit_test_set(true));  \
    S2N_TEST_OPTIONALLY_ENABLE_FIPS_MODE();                    \
    EXPECT_SUCCESS_WITHOUT_COUNT(s2n_init());                  \
    fprintf(stdout, "Running %-50s ... ", __FILE__);           \
  } while(0)

#define END_TEST()   do { \
                        EXPECT_SUCCESS_WITHOUT_COUNT(s2n_in_unit_test_set(false));      \
                        EXPECT_SUCCESS_WITHOUT_COUNT(s2n_cleanup());       \
                        if (isatty(fileno(stdout))) { \
                            if (test_count) { \
                                fprintf(stdout, "\033[32;1mPASSED\033[0m %10d tests\n", test_count ); \
                            }\
                            else {\
                                fprintf(stdout, "\033[33;1mSKIPPED\033[0m       ALL tests\n" ); \
                            }\
                       } \
                       else { \
                            if (test_count) { \
                                fprintf(stdout, "PASSED %10d tests\n", test_count ); \
                            }\
                            else {\
                                fprintf(stdout, "SKIPPED       ALL tests\n" ); \
                            }\
                       } \
                       return 0;\
                    } while(0)

#define FAIL()      FAIL_MSG("")

#define FAIL_MSG( msg ) do { \
                          FAIL_MSG_PRINT(msg); \
                          exit(1);  \
                        } while(0)

#define FAIL_MSG_PRINT( msg ) do { \
                          s2n_print_stacktrace(stderr); \
                          /* isatty will overwrite errno on failure */ \
                          int real_errno = errno; \
                          if (isatty(fileno(stderr))) { \
                            errno = real_errno; \
                            fprintf(stderr, "\033[31;1mFAILED test %d\033[0m\n%s (%s line %d)\nError Message: '%s'\n Debug String: '%s'\n System Error: %s (%d)\n", test_count, (msg), __FILE__, __LINE__, s2n_strerror(s2n_errno, "EN"), s2n_debug_str, strerror(errno), errno); \
                          } \
                          else { \
                            errno = real_errno; \
                            fprintf(stderr, "FAILED test %d\n%s (%s line %d)\nError Message: '%s'\n Debug String: '%s'\n System Error: %s (%d)\n", test_count, (msg), __FILE__, __LINE__, s2n_strerror(s2n_errno, "EN"), s2n_debug_str, strerror(errno), errno); \
                          } \
                        } while(0)

#define RESET_ERRNO() \
    do { \
        s2n_errno = 0; \
        s2n_debug_str = NULL; \
        errno = 0; \
    } while(0);

#define EXPECT_TRUE( condition )    do { test_count++; if ( !(condition) ) { FAIL_MSG( #condition " is not true "); } } while(0)
#define EXPECT_FALSE( condition )   EXPECT_TRUE( !(condition) )

#define EXPECT_EQUAL( p1, p2 )      EXPECT_TRUE( (p1) == (p2) )
#define EXPECT_NOT_EQUAL( p1, p2 )  EXPECT_FALSE( (p1) == (p2) )

#define EXPECT_NULL( ptr )      EXPECT_EQUAL( ptr, NULL )
#define EXPECT_NOT_NULL( ptr )  EXPECT_NOT_EQUAL( ptr, NULL )

#define EXPECT_FAILURE( function_call ) \
    do { \
        EXPECT_EQUAL( (function_call) ,  -1 ); \
        EXPECT_NOT_EQUAL(s2n_errno, 0); \
        EXPECT_NOT_NULL(s2n_debug_str); \
        RESET_ERRNO(); \
    } while(0)
#define EXPECT_ERROR( function_call ) \
    do { \
        EXPECT_TRUE( s2n_result_is_error(function_call) ); \
        EXPECT_NOT_EQUAL(s2n_errno, 0); \
        EXPECT_NOT_NULL(s2n_debug_str); \
        RESET_ERRNO(); \
    } while(0)

#define EXPECT_FAILURE_WITH_ERRNO_NO_RESET( function_call, err ) \
    do { \
        EXPECT_EQUAL( (function_call), -1 ); \
        EXPECT_EQUAL(s2n_errno, err); \
        EXPECT_NOT_NULL(s2n_debug_str); \
    } while(0)

#define EXPECT_FAILURE_WITH_ERRNO( function_call, err ) \
    do { \
        EXPECT_FAILURE_WITH_ERRNO_NO_RESET( function_call, err ); \
        RESET_ERRNO(); \
    } while(0)

/* for use with S2N_RESULT */
#define EXPECT_ERROR_WITH_ERRNO_NO_RESET( function_call, err ) \
    do { \
        EXPECT_TRUE( s2n_result_is_error(function_call) ); \
        EXPECT_EQUAL(s2n_errno, err); \
        EXPECT_NOT_NULL(s2n_debug_str); \
    } while(0)

/* for use with S2N_RESULT */
#define EXPECT_ERROR_WITH_ERRNO( function_call, err ) \
    do { \
        EXPECT_ERROR_WITH_ERRNO_NO_RESET( function_call, err ); \
        RESET_ERRNO(); \
    } while(0)

#define EXPECT_SUCCESS( function_call )  EXPECT_NOT_EQUAL( (function_call) ,  -1 )
/* for use with S2N_RESULT */
#define EXPECT_OK( function_call )  EXPECT_TRUE( s2n_result_is_ok(function_call) )

#define EXPECT_BYTEARRAY_EQUAL( p1, p2, l ) EXPECT_EQUAL( memcmp( (p1), (p2), (l) ), 0 )
#define EXPECT_BYTEARRAY_NOT_EQUAL( p1, p2, l ) EXPECT_NOT_EQUAL( memcmp( (p1), (p2), (l) ), 0 )

#define EXPECT_STRING_EQUAL( p1, p2 ) EXPECT_EQUAL( strcmp( (p1), (p2) ), 0 )
#define EXPECT_STRING_NOT_EQUAL( p1, p2 ) EXPECT_NOT_EQUAL( strcmp( (p1), (p2) ), 0 )

#ifdef S2N_TEST_IN_FIPS_MODE
#include <openssl/err.h>

#define S2N_TEST_OPTIONALLY_ENABLE_FIPS_MODE() \
    do { \
        if (FIPS_mode_set(1) == 0) { \
            unsigned long fips_rc = ERR_get_error(); \
            char ssl_error_buf[256]; \
            fprintf(stderr, "s2nd failed to enter FIPS mode with RC: %lu; String: %s\n", fips_rc, ERR_error_string(fips_rc, ssl_error_buf)); \
            return 1; \
        } \
        printf("s2nd entered FIPS mode\n"); \
    } while (0)

#else
#define S2N_TEST_OPTIONALLY_ENABLE_FIPS_MODE()
#endif

/* Ensures fuzz test input length is greater than or equal to the minimum needed for the test */
#define S2N_FUZZ_ENSURE_MIN_LEN( len , min ) do {if ( (len) < (min) ) return S2N_SUCCESS;} while (0)

#define EXPECT_MEMCPY_SUCCESS(d, s, n)                                         \
    do {                                                                       \
        __typeof(n) __tmp_n = (n);                                             \
        if (__tmp_n) {                                                         \
            if (memcpy((d), (s), (__tmp_n)) == NULL) {                         \
                FAIL_MSG(#d "is NULL, memcpy() failed");                       \
            }                                                                  \
        }                                                                      \
    } while (0)

#if defined(S2N_TEST_DEBUG)
#define TEST_DEBUG_PRINT(...)                \
    do {                                     \
        (void) fprintf(stderr, __VA_ARGS__); \
    } while (0)
#else
#define TEST_DEBUG_PRINT(...)
#endif

/* Creates a fuzz target */
#define S2N_FUZZ_TARGET(fuzz_init, fuzz_entry, fuzz_cleanup) \
void s2n_test__fuzz_cleanup() \
{ \
    if (fuzz_cleanup) { \
        ((void (*)()) fuzz_cleanup)(); \
    } \
    s2n_cleanup(); \
} \
int LLVMFuzzerInitialize(int *argc, char **argv[]) \
{ \
    S2N_TEST_OPTIONALLY_ENABLE_FIPS_MODE(); \
    EXPECT_SUCCESS_WITHOUT_COUNT(s2n_init()); \
    EXPECT_SUCCESS_WITHOUT_COUNT(atexit(s2n_test__fuzz_cleanup)); \
    if (!fuzz_init) { \
        return S2N_SUCCESS; \
    } \
    int result = ((int (*)(int *argc, char **argv[])) fuzz_init)(argc, argv); \
    if (result != S2N_SUCCESS) { \
        FAIL_MSG_PRINT(#fuzz_init " did not return S2N_SUCCESS"); \
    } \
    return result; \
} \
int LLVMFuzzerTestOneInput(const uint8_t *buf, size_t len) \
{ \
    int result = fuzz_entry(buf, len); \
    if (result != S2N_SUCCESS) { \
        FAIL_MSG_PRINT(#fuzz_entry " did not return S2N_SUCCESS"); \
    } \
    return result; \
}
