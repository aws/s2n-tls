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

#include <assert.h>
#include <cbmc_proof/nondet.h>
#include <errno.h>
#include <sys/fcntl.h>

static bool loop_flag = false;

int open(const char *path, int flag, ...)
{
    assert(path != NULL);
    assert(flag == O_RDONLY || flag == O_WRONLY || flag == O_RDWR);
    int rval = 0;
    errno    = nondet_int();
    if (loop_flag) {
        __CPROVER_assume(errno != EINTR);
        return rval;
    }
    loop_flag = true;
    rval      = nondet_int();
    __CPROVER_assume(rval >= -1 && rval <= 65536 /* File descriptor limit. */);
    return rval;
}
