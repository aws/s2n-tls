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
#include "utils/s2n_blob.h"

#include <assert.h>
#include <cbmc_proof/proof_allocators.h>
#include <cbmc_proof/make_common_datastructures.h>

void s2n_calculate_stacktrace() {
}

void s2n_stuffer_rewind_read_harness() {
	struct s2n_stuffer *stuffer = can_fail_malloc(sizeof(struct s2n_stuffer));
	__CPROVER_assume(s2n_stuffer_is_valid(stuffer));
	uint32_t size;
	int ret = s2n_stuffer_rewind_read(stuffer, size);
	if (ret != 0) {
		assert(stuffer->read_cursor < size);
	}
	assert(s2n_stuffer_is_valid(stuffer));
}
