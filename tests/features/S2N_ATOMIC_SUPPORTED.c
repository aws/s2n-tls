/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

#include <signal.h>
#include <stddef.h>

int main() {
    /* Atomic builtins are supported by gcc 4.7.3 and later. */
    sig_atomic_t atomic = 0, value = 1;
    __atomic_store(&atomic, &value, __ATOMIC_RELAXED);
    __atomic_load(&atomic, &value, __ATOMIC_RELAXED);

    /* _Static_assert is supported for C99 by gcc 4.6 and later,
     * so using it here shouldn't limit use of the atomic builtins. */
    _Static_assert(__atomic_always_lock_free(sizeof(sig_atomic_t), NULL),
            "Atomic operations in this environment would require locking");
    return 0;
}
