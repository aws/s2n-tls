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

#include <cbmc_proof/make_common_datastructures.h>
void ensure_s2n_blob_has_allocated_fields(struct s2n_blob* blob) {
    if(blob->growable) {
        blob->data = (blob->allocated == 0) ? NULL : bounded_malloc(blob->allocated);
    } else {
        blob->data = (blob->size == 0) ? NULL : bounded_malloc(blob->size);
    }
}

struct s2n_blob* cbmc_allocate_s2n_blob() {
    struct s2n_blob* blob = can_fail_malloc(sizeof(*blob));
    if (blob !=  NULL) {
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
    if (stuffer != NULL) {
        ensure_s2n_stuffer_has_allocated_fields(stuffer);
    }
    return stuffer;
}

const char *ensure_c_str_is_allocated(size_t max_size) {
    size_t cap;
    __CPROVER_assume(cap > 0 && cap <= max_size);
    const char *str = bounded_malloc(cap);
    /* Ensure that its a valid c string. Since all bytes are nondeterminstic, the actual
     * string length is 0..str_cap
     */
    __CPROVER_assume(str[cap - 1] == 0);
    return str;
}
