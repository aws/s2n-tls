/*
 * Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

#include "api/s2n.h"
#include "stuffer/s2n_stuffer.h"
#include <assert.h>
#include <cbmc_proof/proof_allocators.h>
#include <cbmc_proof/make_common_datastructures.h>

void s2n_calculate_stacktrace() {
}

bool s2n_blob_is_valid(const struct s2n_blob* b);
bool nondet_bool();

/* The reason we don't have full coverage is that we only have a s2n_realloc function,
and in this case we are only allocating for the first time */
void s2n_stuffer_resize_if_empty_harness() {
	struct s2n_stuffer *stuffer = cbmc_allocate_s2n_stuffer();
    __CPROVER_assume(s2n_stuffer_is_valid(stuffer));
    stuffer->blob.data = nondet_bool() ? stuffer->blob.data : NULL;
	uint32_t size;
	int ret = s2n_stuffer_resize_if_empty(stuffer, size);
}
