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

#define _GNU_SOURCE

#include <stdio.h>
#include <dlfcn.h>

#include "api/s2n.h"
#include "error/s2n_errno.h"

#include "stuffer/s2n_stuffer.h"

#include "utils/s2n_safety.h"
#include "utils/s2n_random.h"

S2N_RESULT s2n_get_public_random_data(struct s2n_blob *blob){

    /* If fuzzing, only generate "fake" random numbers in order to ensure that fuzz tests are deterministic and repeatable.
     * This function should generate non-zero values since this function may be called repeatedly at startup until a
     * non-zero value is generated.
     */
    for(int i=0; i < blob->size; i++){
       blob->data[i] = 4; /* Fake RNG. Chosen by fair dice roll. https://xkcd.com/221/ */
    }
    return S2N_RESULT_OK;
}
