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

#include <sys/param.h>

#include "utils/s2n_blob.h"
#include "utils/s2n_mem.h"
#include "utils/s2n_safety.h"
#include "utils/s2n_array.h"

S2N_RESULT s2n_array_validate(const struct s2n_array *array)
{
    uint32_t mem_size = 0;
    RESULT_ENSURE_REF(array);
    RESULT_GUARD(s2n_blob_validate(&array->mem));
    RESULT_ENSURE_NE(array->element_size, 0);
    RESULT_GUARD_POSIX(s2n_mul_overflow(array->len, array->element_size, &mem_size));
    RESULT_ENSURE_GTE(array->mem.size, mem_size);
    return S2N_RESULT_OK;
}

static S2N_RESULT s2n_array_enlarge(struct s2n_array *array, uint32_t capacity)
{
    RESULT_ENSURE_REF(array);

    /* Acquire the memory */
    uint32_t mem_needed;
    RESULT_GUARD_POSIX(s2n_mul_overflow(array->element_size, capacity, &mem_needed));
    RESULT_GUARD_POSIX(s2n_realloc(&array->mem, mem_needed));

    /* Zero the extened part */
    uint32_t array_elements_size;
    RESULT_GUARD_POSIX(s2n_mul_overflow(array->element_size, array->len, &array_elements_size));
    RESULT_CHECKED_MEMSET(array->mem.data + array_elements_size, 0, array->mem.size - array_elements_size);
    RESULT_GUARD(s2n_array_validate(array));
    return S2N_RESULT_OK;
}

struct s2n_array *s2n_array_new(uint32_t element_size)
{
    struct s2n_blob mem = {0};
    PTR_GUARD_POSIX(s2n_alloc(&mem, sizeof(struct s2n_array)));

    struct s2n_array *array = (void *) mem.data;

    *array = (struct s2n_array) {.mem = {0}, .len = 0, .element_size = element_size};

    if (s2n_result_is_error(s2n_array_enlarge(array, S2N_INITIAL_ARRAY_SIZE))) {
        /* Avoid memory leak if allocation fails */
        PTR_GUARD_POSIX(s2n_free(&mem));
        return NULL;
    }
    return array;
}

S2N_RESULT s2n_array_init(struct s2n_array *array, uint32_t element_size)
{
    RESULT_ENSURE_REF(array);

    *array = (struct s2n_array){.element_size = element_size};

    RESULT_GUARD(s2n_array_validate(array));
    return S2N_RESULT_OK;
}

S2N_RESULT s2n_array_pushback(struct s2n_array *array, void **element)
{
    RESULT_GUARD(s2n_array_validate(array));
    RESULT_ENSURE_REF(element);
    return s2n_array_insert(array, array->len, element);
}

S2N_RESULT s2n_array_get(struct s2n_array *array, uint32_t idx, void **element)
{
    RESULT_GUARD(s2n_array_validate(array));
    RESULT_ENSURE_REF(element);
    RESULT_ENSURE(idx < array->len, S2N_ERR_ARRAY_INDEX_OOB);
    *element = array->mem.data + (array->element_size * idx);
    return S2N_RESULT_OK;
}

S2N_RESULT s2n_array_insert_and_copy(struct s2n_array *array, uint32_t idx, void* element)
{
    void* insert_location = NULL;
    RESULT_GUARD(s2n_array_insert(array, idx, &insert_location));
    RESULT_CHECKED_MEMCPY(insert_location, element, array->element_size);
    return S2N_RESULT_OK;
}

S2N_RESULT s2n_array_insert(struct s2n_array *array, uint32_t idx, void **element)
{
    RESULT_GUARD(s2n_array_validate(array));
    RESULT_ENSURE_REF(element);
    /* index == len is ok since we're about to add one element */
    RESULT_ENSURE(idx <= array->len, S2N_ERR_ARRAY_INDEX_OOB);

    /* We are about to add one more element to the array. Add capacity if necessary */
    uint32_t current_capacity = 0;
    RESULT_GUARD(s2n_array_capacity(array, &current_capacity));

    if (array->len >= current_capacity) {
        /* Enlarge the array */
        uint32_t new_capacity = 0;
        RESULT_GUARD_POSIX(s2n_mul_overflow(current_capacity, 2, &new_capacity));
        new_capacity = MAX(new_capacity, S2N_INITIAL_ARRAY_SIZE);
        RESULT_GUARD(s2n_array_enlarge(array, new_capacity));
    }

    /* If we are adding at an existing index, slide everything down. */
    if (idx < array->len) {
        memmove(array->mem.data + array->element_size * (idx + 1),
                array->mem.data + array->element_size * idx,
                (array->len - idx) * array->element_size);
    }

    *element = array->mem.data + array->element_size * idx;
    array->len++;

    RESULT_GUARD(s2n_array_validate(array));
    return S2N_RESULT_OK;
}

S2N_RESULT s2n_array_remove(struct s2n_array *array, uint32_t idx)
{
    RESULT_GUARD(s2n_array_validate(array));
    RESULT_ENSURE(idx < array->len, S2N_ERR_ARRAY_INDEX_OOB);

    /* If the removed element is the last one, no need to move anything.
     * Otherwise, shift everything down */
    if (idx != array->len - 1) {
        memmove(array->mem.data + array->element_size * idx,
                array->mem.data + array->element_size * (idx + 1),
                (array->len - idx - 1) * array->element_size);
    }
    array->len--;

    /* After shifting, zero the last element */
    RESULT_CHECKED_MEMSET(array->mem.data + array->element_size * array->len,
                   0,
                   array->element_size);

    return S2N_RESULT_OK;
}

S2N_RESULT s2n_array_num_elements(struct s2n_array *array, uint32_t *len)
{
    RESULT_GUARD(s2n_array_validate(array));
    RESULT_ENSURE_MUT(len);

    *len = array->len;

    return S2N_RESULT_OK;
}

S2N_RESULT s2n_array_capacity(struct s2n_array *array, uint32_t *capacity)
{
    RESULT_GUARD(s2n_array_validate(array));
    RESULT_ENSURE_MUT(capacity);

    *capacity = array->mem.size / array->element_size;

    return S2N_RESULT_OK;
}

S2N_RESULT s2n_array_free_p(struct s2n_array **parray)
{
    RESULT_ENSURE_REF(parray);
    struct s2n_array *array = *parray;

    RESULT_ENSURE_REF(array);
    /* Free the elements */
    RESULT_GUARD_POSIX(s2n_free(&array->mem));

    /* And finally the array */
    RESULT_GUARD_POSIX(s2n_free_object((uint8_t **)parray, sizeof(struct s2n_array)));

    return S2N_RESULT_OK;
}

S2N_RESULT s2n_array_free(struct s2n_array *array)
{
    RESULT_ENSURE_REF(array);
    return s2n_array_free_p(&array);
}
