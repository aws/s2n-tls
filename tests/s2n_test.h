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
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/crypto.h>

#include "error/s2n_errno.h"
#include "utils/s2n_safety.h"

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
#ifdef S2N_TEST_IN_FIPS_MODE
#define BEGIN_TEST()						\
  int test_count = 0;						\
  do {								\
    EXPECT_SUCCESS_WITHOUT_COUNT(s2n_in_unit_test_set(true));	\
    EXPECT_NOT_EQUAL_WITHOUT_COUNT(FIPS_mode_set(1), 0);	\
    EXPECT_SUCCESS_WITHOUT_COUNT(s2n_init());			\
    fprintf(stdout, "Running FIPS test %-50s ... ", __FILE__);	\
  } while(0)
#else
#define BEGIN_TEST()						\
  int test_count = 0; do {					\
    EXPECT_SUCCESS_WITHOUT_COUNT(s2n_in_unit_test_set(true));	\
    EXPECT_SUCCESS_WITHOUT_COUNT(s2n_init());			\
    fprintf(stdout, "Running %-50s ... ", __FILE__);		\
  } while(0)
#endif
#define END_TEST()   do { \
                        EXPECT_SUCCESS_WITHOUT_COUNT(s2n_in_unit_test_set(false));		\
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
                          s2n_print_stacktrace(stdout); \
                          /* isatty will overwrite errno on failure */ \
                          int real_errno = errno; \
                          if (isatty(fileno(stdout))) { \
                            errno = real_errno; \
                            fprintf(stdout, "\033[31;1mFAILED test %d\033[0m\n%s (%s line %d)\nError Message: '%s'\n Debug String: '%s'\n System Error: %s (%d)\n", test_count, (msg), __FILE__, __LINE__, s2n_strerror(s2n_errno, "EN"), s2n_debug_str, strerror(errno), errno); \
                          } \
                          else { \
                            errno = real_errno; \
                            fprintf(stdout, "FAILED test %d\n%s (%s line %d)\nError Message: '%s'\n Debug String: '%s'\n System Error: %s (%d)\n", test_count, (msg), __FILE__, __LINE__, s2n_strerror(s2n_errno, "EN"), s2n_debug_str, strerror(errno), errno); \
                          } \
                          exit(1);  \
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

#define EXPECT_SUCCESS( function_call )  EXPECT_NOT_EQUAL( (function_call) ,  -1 )

#define EXPECT_BYTEARRAY_EQUAL( p1, p2, l ) EXPECT_EQUAL( memcmp( (p1), (p2), (l) ), 0 )
#define EXPECT_BYTEARRAY_NOT_EQUAL( p1, p2, l ) EXPECT_NOT_EQUAL( memcmp( (p1), (p2), (l) ), 0 )

#define EXPECT_STRING_EQUAL( p1, p2 ) EXPECT_EQUAL( strcmp( (p1), (p2) ), 0 )

#define S2N_TEST_ENTER_FIPS_MODE()    { if (FIPS_mode_set(1) == 0) { \
                                            unsigned long fips_rc = ERR_get_error(); \
                                            char ssl_error_buf[256]; \
                                            fprintf(stderr, "s2nd failed to enter FIPS mode with RC: %lu; String: %s\n", fips_rc, ERR_error_string(fips_rc, ssl_error_buf)); \
                                            return 1; \
                                        } \
                                        printf("s2nd entered FIPS mode\n"); \
                                      }
