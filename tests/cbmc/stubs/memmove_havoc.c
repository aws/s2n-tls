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

#include <cbmc_proof/nondet.h>
#include <stdint.h>

/**
 * Override the version of memmove used by CBMC. Users may not want to pay
 * for the cost of performing the computation of memmove in proofs. In that
 * case, this stub at least checks for the preconditions and make sure to
 * havoc all elements pointed by *dest up to n.
 */
void *memmove_impl(void *dest, const void *src, size_t n) {
__CPROVER_HIDE:;
    __CPROVER_precondition(src != NULL && __CPROVER_r_ok(src, n), "memmove source region readable");
    __CPROVER_precondition(dest != NULL && __CPROVER_w_ok(dest, n), "memmove destination region writeable");

    if (n > 0) {
        size_t idx;
        __CPROVER_assume(idx < n);
        ((uint8_t *)dest)[idx] = nondet_uint8_t();
    }

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
