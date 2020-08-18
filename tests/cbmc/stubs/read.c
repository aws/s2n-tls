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

#include <cbmc_proof/nondet.h>
#include <errno.h>
#include <unistd.h>

static bool loop_flag = false;

ssize_t read(int fd, void *buf, size_t nbyte)
{
    errno = nondet_int();
    if (loop_flag) {
        __CPROVER_assume(errno != EINTR);
        return 0;
    }
    loop_flag = true;
    ssize_t rval;
    __CPROVER_assume(rval <= ( ssize_t )nbyte);
    return rval;
}
