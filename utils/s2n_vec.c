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
#include "utils/s2n_blob.h"
#include "utils/s2n_mem.h"
#include "utils/s2n_safety.h"
#include "utils/s2n_vec.h"

#define S2N_INITIAL_VEC_SIZE 16

static S2N_RESULT s2n_vec_enlarge(struct s2n_vec *vec, uint32_t capacity)
{
    ENSURE_NONNULL(vec);

    /* Acquire the memory */
    uint32_t mem_needed;
    GUARD_AS_RESULT(s2n_mul_overflow(vec->element_size, capacity, &mem_needed));
    GUARD_AS_RESULT(s2n_realloc(&vec->mem, mem_needed));

    /* Zero the extened part */
    uint32_t vec_elements_size;
    GUARD_AS_RESULT(s2n_mul_overflow(vec->element_size, vec->len, &vec_elements_size));
    CHECKED_MEMSET(vec->mem.data + vec_elements_size, 0, vec->mem.size - vec_elements_size);

    return S2N_RESULT_OK;
}

struct s2n_vec *s2n_vec_new(size_t element_size)
{
    struct s2n_blob mem = {0};
    GUARD_PTR(s2n_alloc(&mem, sizeof(struct s2n_vec)));

    struct s2n_vec *vec = (void *) mem.data;
    *vec = (struct s2n_vec) {.mem = {0}, .len = 0, .element_size = element_size};

    if (s2n_result_is_error(s2n_vec_enlarge(vec, S2N_INITIAL_VEC_SIZE))) {
        /* Avoid memory leak if allocation fails */
        GUARD_PTR(s2n_free(&mem));
        return NULL;
    }
    return vec;
}

S2N_RESULT s2n_vec_pushback(struct s2n_vec *vec, void **element)
{
    ENSURE_NONNULL(vec);
    ENSURE_NONNULL(element);
    return s2n_vec_insert(vec, vec->len, element);
}

S2N_RESULT s2n_vec_get(struct s2n_vec *vec, uint32_t index, void **element)
{
    ENSURE_NONNULL(vec);
    ENSURE_NONNULL(element);
    ENSURE(index < vec->len, S2N_ERR_VEC_INDEX_OOB);
    *element = vec->mem.data + vec->element_size * index;
    return S2N_RESULT_OK;
}

S2N_RESULT s2n_vec_insert_and_copy(struct s2n_vec *vec, uint32_t index, void* element)
{
    void* insert_location = NULL;
    GUARD_RESULT(s2n_vec_insert(vec, index, &insert_location));
    CHECKED_MEMCPY(insert_location, element, vec->element_size);
    return S2N_RESULT_OK;
}

S2N_RESULT s2n_vec_insert(struct s2n_vec *vec, uint32_t index, void **element)
{
    ENSURE_NONNULL(vec);
    ENSURE_NONNULL(element);
    /* index == len is ok since we're about to add one element */
    ENSURE(index <= vec->len, S2N_ERR_VEC_INDEX_OOB);

    /* We are about to add one more element to the vec. Add capacity if necessary */
    uint32_t current_capacity = 0;
    GUARD_RESULT(s2n_vec_capacity(vec, &current_capacity));
    if (vec->len >= current_capacity) {
        /* Enlarge the vec */
        uint32_t new_capacity;
        GUARD_AS_RESULT(s2n_mul_overflow(current_capacity, 2, &new_capacity));
        GUARD_RESULT(s2n_vec_enlarge(vec, new_capacity));
    }

    /* If we are adding at an existing index, slide everything down. */
    if (index < vec->len) {
        memmove(vec->mem.data + vec->element_size * (index + 1),
                vec->mem.data + vec->element_size * index,
                (vec->len - index) * vec->element_size);
    }

    *element = vec->mem.data + vec->element_size * index;
    vec->len++;

    return S2N_RESULT_OK;
}

S2N_RESULT s2n_vec_remove(struct s2n_vec *vec, uint32_t index)
{
    ENSURE_NONNULL(vec);
    ENSURE(index < vec->len, S2N_ERR_VEC_INDEX_OOB);

    /* If the removed element is the last one, no need to move anything.
     * Otherwise, shift everything down */
    if (index != vec->len - 1) {
        memmove(vec->mem.data + vec->element_size * index,
                vec->mem.data + vec->element_size * (index + 1),
                (vec->len - index - 1) * vec->element_size);
    }
    vec->len--;

    /* After shifting, zero the last element */
    CHECKED_MEMSET(vec->mem.data + vec->element_size * vec->len,
                   0,
                   vec->element_size);

    return S2N_RESULT_OK;
}

S2N_RESULT s2n_vec_len(struct s2n_vec *vec, uint32_t *len)
{
    ENSURE_NONNULL(vec);

    *len = vec->len;

    return S2N_RESULT_OK;
}

S2N_RESULT s2n_vec_capacity(struct s2n_vec *vec, uint32_t *capacity)
{
    ENSURE_NONNULL(vec);

    *capacity = vec->mem.size / vec->element_size;

    return S2N_RESULT_OK;
}

S2N_RESULT s2n_vec_free_p(struct s2n_vec **parray)
{
    ENSURE_NONNULL(parray);
    struct s2n_vec *array = *parray;

    ENSURE_NONNULL(array);
    /* Free the elements */
    GUARD_AS_RESULT(s2n_free(&array->mem));

    /* And finally the array */
    GUARD_AS_RESULT(s2n_free_object((uint8_t **)parray, sizeof(struct s2n_vec)));

    return S2N_RESULT_OK;
}

S2N_RESULT s2n_vec_free(struct s2n_vec *vec)
{
    return s2n_vec_free_p(&vec);
}
