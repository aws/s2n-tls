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

#include <assert.h>
#include <cbmc_proof/make_common_datastructures.h>

#include "api/s2n.h"
#include "stuffer/s2n_stuffer.h"

void s2n_stuffer_init_harness()
{
    struct s2n_stuffer *stuffer = malloc(sizeof(*stuffer));
    struct s2n_blob *   in      = cbmc_allocate_s2n_blob();
    if (s2n_stuffer_init(stuffer, in) == S2N_SUCCESS) {
        assert(s2n_result_is_ok(s2n_stuffer_validate(stuffer)));
        assert(s2n_result_is_ok(s2n_blob_validate(in)));
    };
}
