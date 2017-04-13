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

#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>

#include "error/s2n_errno.h"

/**
 * This is a very basic, but functional unit testing framework. All testing should
 * happen in main() and start with a BEGIN_TEST() and end with an END_TEST();
 *
 */

#define BEGIN_TEST() int test_count = 0; EXPECT_SUCCESS(s2n_init()); { fprintf(stdout, "Running %-50s ... ", __FILE__); }
#define END_TEST()   EXPECT_SUCCESS(s2n_cleanup()); { if (isatty(fileno(stdout))) { \
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
                    }

#define FAIL()      FAIL_MSG("");

#define FAIL_MSG( msg ) { if (isatty(fileno(stdout))) { \
                            fprintf(stdout, "\033[31;1mFAILED test %d\033[0m\n%s (%s line %d)\nError Message: '%s'\n Debug String: '%s'\n", test_count, (msg), __FILE__, __LINE__, s2n_strerror(s2n_errno, "EN"), s2n_debug_str); \
                          } \
                          else { \
                            fprintf(stdout, "FAILED test %d\n%s (%s line %d)\nError Message: '%s'\n Debug String: '%s'\n", test_count, (msg), __FILE__, __LINE__, s2n_strerror(s2n_errno, "EN"), s2n_debug_str); \
                          } \
                          exit(1);  \
                        }

#define EXPECT_TRUE( condition )    { test_count++; if ( !(condition) ) { FAIL_MSG( #condition " is not true "); } }
#define EXPECT_FALSE( condition )   EXPECT_TRUE( !(condition) )

#define EXPECT_EQUAL( p1, p2 )      EXPECT_TRUE( (p1) == (p2) )
#define EXPECT_NOT_EQUAL( p1, p2 )  EXPECT_FALSE( (p1) == (p2) )

#define EXPECT_NULL( ptr )      EXPECT_EQUAL( ptr, NULL )
#define EXPECT_NOT_NULL( ptr )  EXPECT_NOT_EQUAL( ptr, NULL )

#define EXPECT_FAILURE( function_call )  { EXPECT_EQUAL( (function_call) ,  -1 ); EXPECT_NOT_EQUAL(s2n_errno, 0); EXPECT_NOT_NULL(s2n_debug_str); s2n_errno = 0; s2n_debug_str = NULL; }
#define EXPECT_SUCCESS( function_call )  EXPECT_NOT_EQUAL( (function_call) ,  -1 )

#define EXPECT_BYTEARRAY_EQUAL( p1, p2, l ) EXPECT_EQUAL( memcmp( (p1), (p2), (l) ), 0 )
#define EXPECT_STRING_EQUAL( p1, p2 ) EXPECT_EQUAL( strcmp( (p1), (p2) ), 0 )
