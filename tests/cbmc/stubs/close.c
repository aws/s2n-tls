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
#include <unistd.h>

static bool loop_flag = false;

int close(int fd)
{
    assert(fd >= -1 && fd <= 65536 /* File descriptor limit. */);
    if (nondet_bool()) { return 0; }
    __CPROVER_assume(errno == EBADF || errno == EINTR || errno == EIO);
    return -1;
}
