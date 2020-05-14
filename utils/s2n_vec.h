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
#pragma once

#include <s2n.h>
#include "utils/s2n_blob.h"
#include "utils/s2n_result.h"

struct s2n_vec {
    /* Pointer to elements in vector */
    struct s2n_blob mem;

    /* The total number of elements currently in the vector. */
    uint32_t len;

    /* The size of each element in the vector */
    size_t element_size;
};

extern struct s2n_vec *s2n_vec_new(size_t element_size);
extern S2N_RESULT s2n_vec_pushback(struct s2n_vec *vec, void **element);
extern S2N_RESULT s2n_vec_get(struct s2n_vec *vec, uint32_t index, void **element);
extern S2N_RESULT s2n_vec_insert(struct s2n_vec *vec, uint32_t index, void **element);
extern S2N_RESULT s2n_vec_insert_and_copy(struct s2n_vec *vec, uint32_t index, void *element);
extern S2N_RESULT s2n_vec_len(struct s2n_vec *vec, uint32_t *len);
extern S2N_RESULT s2n_vec_capacity(struct s2n_vec *vec, uint32_t *capacity);
extern S2N_RESULT s2n_vec_remove(struct s2n_vec *vec, uint32_t index);
extern S2N_RESULT s2n_vec_free_p(struct s2n_vec **pvec);
extern S2N_RESULT s2n_vec_free(struct s2n_vec *vec);
