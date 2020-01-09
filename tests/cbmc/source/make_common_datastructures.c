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

#include <cbmc_proof/make_common_datastructures.h>
void ensure_s2n_blob_has_allocated_fields(struct s2n_blob* blob) {
    blob->data = bounded_malloc(blob->size);
}

struct s2n_blob* cbmc_allocate_s2n_blob() {
    struct s2n_blob* blob = can_fail_malloc(sizeof(*blob));
    if (blob) {
	ensure_s2n_blob_has_allocated_fields(blob);
    }
    return blob;
}

void ensure_s2n_stuffer_has_allocated_fields(struct s2n_stuffer* stuffer)
{
    ensure_s2n_blob_has_allocated_fields(&stuffer->blob);
}

struct s2n_stuffer* cbmc_allocate_s2n_stuffer() {
    struct s2n_stuffer* stuffer = can_fail_malloc(sizeof(*stuffer));
    if (stuffer) {
	ensure_s2n_stuffer_has_allocated_fields(stuffer);
    }
    return stuffer;
}
