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

#undef posix_memalign

#include <cbmc_proof/nondet.h>
#include <errno.h>
#include <stdint.h>

/**
 * Overrides the version of posix_memalign used by CBMC.
 * The current CBMC model doesn't consider malloc may fail.
 */
int posix_memalign(void **ptr, __CPROVER_size_t alignment, __CPROVER_size_t size)
{
    __CPROVER_HIDE:;

    __CPROVER_size_t multiplier = alignment / sizeof(void *);
    /* Modeling the posix_memalign checks on alignment. */
    if (alignment % sizeof(void *) != 0 ||
        ((multiplier) & (multiplier - 1)) != 0 || alignment == 0) {
      return EINVAL;
    }
    void *tmp = malloc(size);
    if(tmp != NULL) {
        *ptr = tmp;
        return 0;
    }
    return ENOMEM;
}
