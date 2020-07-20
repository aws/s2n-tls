/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"). You may not use
 * this file except in compliance with the License. A copy of the License is
 * located at
 *
 *     http://aws.amazon.com/apache2.0/
 *
 * or in the "license" file accompanying this file. This file is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied. See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <error/s2n_errno.h>

#include <cbmc_proof/make_common_datastructures.h>
#include <cbmc_proof/nondet.h>
#include <errno.h>
#include <unistd.h>

static bool loop_flag = false;

ssize_t write(int fildes, const void *buf, size_t nbyte) {
    ssize_t rval = 0;
    errno = nondet_int();
    if(loop_flag) {
        __CPROVER_assume(errno != EINTR);
        return rval;
    }
    loop_flag = true;
    rval = nondet_ssize_t();
    return rval;
}
