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
#include <cbmc_proof/proof_allocators.h>
#include <sys/fcntl.h>

#include <stdarg.h>

int open(const char *path, int flag, ...) {
    assert(path != NULL);
    assert(flag == O_RDONLY || flag == O_WRONLY || flag == O_RDWR);
    return 0;
}
