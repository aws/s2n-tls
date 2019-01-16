/*
 * Copyright 2016 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

#define _GNU_SOURCE
#include <dlfcn.h>
#include <openssl/rsa.h>
#include <time.h>

#include "crypto/s2n_rsa.h"
#include "error/s2n_errno.h"
#include "tls/s2n_connection.h"
#include "utils/s2n_safety.h"

time_t time (time_t *__timer)
{
    /* Always assume the time is zero when fuzzing the server, this is to ensure that Fuzz tests are deterministic and
     * don't depend on the time the test was run.
     */
    return 0;
}


int RSA_verify(int dtype, const unsigned char *m, unsigned int m_len,
                 const unsigned char *sigbuf, unsigned int siglen, RSA *rsa)
{
    /* Always assume that the RSA_verify function passes */
    return 1;
}

int s2n_constant_time_equals(const uint8_t *a, const uint8_t *b, uint32_t len)
{
    /* Allow all signatures checked with s2n_constant_time_equals to always pass verification even if they are invalid
     * in order to aid code coverage with server fuzz test.
     */
    return 1;
}

int s2n_rsa_client_key_recv(struct s2n_connection *conn, struct s2n_blob *shared_key)
{
    /* Perform the original function */
    typedef int (*orig_s2n_rsa_client_key_recv_func_type)(struct s2n_connection *conn, struct s2n_blob *shared_key);
    orig_s2n_rsa_client_key_recv_func_type orig_s2n_rsa_client_key_recv;
    orig_s2n_rsa_client_key_recv = (orig_s2n_rsa_client_key_recv_func_type) dlsym(RTLD_NEXT, "s2n_rsa_client_key_recv");
    int original_return_code = orig_s2n_rsa_client_key_recv(conn, shared_key);

    /* Then, overwrite the RSA Failed flag to false before returning, this will help fuzzing code coverage. */
    conn->handshake.rsa_failed = 0;

    return original_return_code;
}

