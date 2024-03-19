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

#undef memmove

#include <assert.h>
#include <cbmc_proof/nondet.h>
#include <stdint.h>
#include <stdlib.h>

/**
 * CBMC can struggle to model memmove.
 * If a proof needs real memmove behavior without paying its high cost,
 * that proof can use this simple looping based solution.
 */
void *memmove_impl(void *dest, const void *src, size_t n) {
    __CPROVER_HIDE:;
    if (n > 0) {
        assert(dest);
        assert(src);
    }

    uint8_t *dest_bytes = (uint8_t*) dest;
    uint8_t *src_bytes = (uint8_t*) src;

    /* src and dst can overlap, so we need to save a copy of src
     * in case modifying dst modifies src */
    uint8_t *src_copy = malloc(n);
    if (src_copy == NULL) {
        return NULL;
    }
    for (size_t i = 0; i < n; i++) {
        src_copy[i] = src_bytes[i];
    }

    for (size_t i = 0; i < n; i++) {
        dest_bytes[i] = src_copy[i];
    }

    free(src_copy);
    return dest;
}

void *memmove(void *dest, const void *src, size_t n) {
    __CPROVER_HIDE:;
    return memmove_impl(dest, src, n);
}

void *__builtin___memmove_chk(void *dest, const void *src, size_t n, size_t size) {
    __CPROVER_HIDE:;
    (void)size;
    return memmove_impl(dest, src, n);
}
