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

#include "crypto/s2n_rsa.h"
#include "error/s2n_errno.h"
#include "utils/s2n_safety.h"

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

int accept_all_rsa_certs(struct s2n_blob *cert_chain_in, struct s2n_cert_public_key *public_key_out, void *context)
{
    struct s2n_stuffer cert_chain_in_stuffer;
    GUARD(s2n_stuffer_init(&cert_chain_in_stuffer, cert_chain_in));
    GUARD(s2n_stuffer_write(&cert_chain_in_stuffer, cert_chain_in));

    int certificate_count = 0;
    while (s2n_stuffer_data_available(&cert_chain_in_stuffer)) {
        uint32_t certificate_size;

        GUARD(s2n_stuffer_read_uint24(&cert_chain_in_stuffer, &certificate_size));

        if (certificate_size > s2n_stuffer_data_available(&cert_chain_in_stuffer) || certificate_size == 0) {
            S2N_ERROR(S2N_ERR_BAD_MESSAGE);
        }

        struct s2n_blob asn1cert;
        asn1cert.data = s2n_stuffer_raw_read(&cert_chain_in_stuffer, certificate_size);
        asn1cert.size = certificate_size;
        notnull_check(asn1cert.data);

        gt_check(certificate_size, 0);

        /* Pull the public key from the first certificate */
        if (certificate_count == 0) {
            struct s2n_rsa_public_key *rsa_pub_key_out;
            GUARD(s2n_cert_public_key_get_rsa(public_key_out, &rsa_pub_key_out));
            /* Assume that the asn1cert is an RSA Cert */
            GUARD(s2n_asn1der_to_rsa_public_key(rsa_pub_key_out, &asn1cert));
            GUARD(s2n_cert_public_key_set_cert_type(public_key_out, S2N_CERT_TYPE_RSA_SIGN));
        }

        certificate_count++;
    }

    gte_check(certificate_count, 1);
    return 0;
}
