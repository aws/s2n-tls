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

#include <assert.h>
#include <errno.h>

#include "error/s2n_errno.h"

int madvise(void *addr, size_t length, int advice)
{
    assert(S2N_MEM_IS_WRITABLE(addr, length));
    if (nondet_bool()) { return 0; }
    errno = nondet_int();
    return -1;
}
