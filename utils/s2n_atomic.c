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

#include "utils/s2n_atomic.h"

#include "utils/s2n_safety.h"

const s2n_atomic set_val = 1;
const s2n_atomic clear_val = 0;

S2N_RESULT s2n_atomic_init()
{
#if S2N_ATOMIC_ENABLED
    RESULT_ENSURE(__atomic_always_lock_free(sizeof(s2n_atomic), NULL), S2N_ERR_ATOMIC);
#endif
    return S2N_RESULT_OK;
}

void s2n_atomic_set(s2n_atomic *var)
{
#if S2N_ATOMIC_ENABLED
    __atomic_store(var, &set_val, __ATOMIC_RELAXED);
#else
    *var = 1;
#endif
}

void s2n_atomic_clear(s2n_atomic *var)
{
#if S2N_ATOMIC_ENABLED
    __atomic_store(var, &clear_val, __ATOMIC_RELAXED);
#else
    *var = 0;
#endif
}

bool s2n_atomic_check(s2n_atomic *var)
{
#if S2N_ATOMIC_ENABLED
    s2n_atomic result = 0;
    __atomic_load(var, &result, __ATOMIC_RELAXED);
    return result;
#else
    return *var;
#endif
}
