/*
 * Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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
#include "utils/s2n_array.h"
#include "utils/s2n_blob.h"
#include "utils/s2n_mem.h"
#include "utils/s2n_safety.h"

#define S2N_INITIAL_ARRAY_SIZE 16

static int s2n_array_enlarge(struct s2n_array *array, uint32_t capacity)
{
    notnull_check(array);

    /* Acquire the memory */
    uint32_t mem_needed;
    GUARD(s2n_mul_overflow(array->element_size, capacity, &mem_needed));
    GUARD(s2n_realloc(&array->mem, mem_needed));

    /* Zero the extened part */
    uint32_t array_elements_size;
    GUARD(s2n_mul_overflow(array->element_size, array->num_of_elements, &array_elements_size));
    memset_check(array->mem.data + array_elements_size, 0, array->mem.size - array_elements_size);

    /* Update array capacity */
    array->capacity = capacity;

    return 0;
}

struct s2n_array *s2n_array_new(size_t element_size)
{
    struct s2n_blob mem = {0};
    GUARD_PTR(s2n_alloc(&mem, sizeof(struct s2n_array)));

    struct s2n_array *array = (void *) mem.data;
    *array = (struct s2n_array) {.mem = {0}, .num_of_elements = 0, .capacity = 0, .element_size = element_size};

    if (s2n_array_enlarge(array, S2N_INITIAL_ARRAY_SIZE) < 0) {
        /* Avoid memory leak if allocation fails */
        GUARD_PTR(s2n_free(&mem));
        return NULL;
    }
    return array;
}

void *s2n_array_pushback(struct s2n_array *array)
{
    notnull_check_ptr(array);
    return s2n_array_insert(array, array->num_of_elements);
}

void *s2n_array_get(struct s2n_array *array, uint32_t index)
{
    notnull_check_ptr(array);
    S2N_ERROR_IF_PTR(index >= array->num_of_elements, S2N_ERR_ARRAY_INDEX_OOB);
    return array->mem.data + array->element_size * index;
}

int s2n_array_insert_and_copy(struct s2n_array *array, void* element, uint32_t index)
{
    void* insert_location = NULL;
    GUARD_NONNULL(insert_location = s2n_array_insert(array, index));
    memcpy_check(insert_location, element, array->element_size);
    return S2N_SUCCESS;
}

void *s2n_array_insert(struct s2n_array *array, uint32_t index)
{
    notnull_check_ptr(array);
    /* index == num_of_elements is ok since we're about to add one element */
    S2N_ERROR_IF_PTR(index > array->num_of_elements, S2N_ERR_ARRAY_INDEX_OOB);

    /* We are about to add one more element to the array. Add capacity if necessary */
    if (array->num_of_elements >= array->capacity) {
        /* Enlarge the array */
        uint32_t new_capacity;
        GUARD_PTR(s2n_mul_overflow(array->capacity, 2, &new_capacity));
        GUARD_PTR(s2n_array_enlarge(array, new_capacity));
    }

    /* If we are adding at an existing index, slide everything down. */
    if (index < array->num_of_elements) {
        memmove(array->mem.data + array->element_size * (index + 1),
                array->mem.data + array->element_size * index,
                (array->num_of_elements - index) * array->element_size);
    }

    void *element = array->mem.data + array->element_size * index;
    array->num_of_elements++;

    return element;
}

int s2n_array_remove(struct s2n_array *array, uint32_t index)
{
    notnull_check(array);
    S2N_ERROR_IF(index >= array->num_of_elements, S2N_ERR_ARRAY_INDEX_OOB);

    /* If the removed element is the last one, no need to move anything.
     * Otherwise, shift everything down */
    if (index != array->num_of_elements - 1) {
        memmove(array->mem.data + array->element_size * index,
                array->mem.data + array->element_size * (index + 1),
                (array->num_of_elements - index - 1) * array->element_size);
    }
    array->num_of_elements--;

    /* After shifting, zero the last element */
    memset_check(array->mem.data + array->element_size * array->num_of_elements,
                  0,
                  array->element_size);

    return 0;
}

int s2n_array_free_p(struct s2n_array **parray)
{
    notnull_check(parray);
    struct s2n_array *array = *parray;

    notnull_check(array);
    /* Free the elements */
    GUARD(s2n_free(&array->mem));

    /* And finally the array */
    GUARD(s2n_free_object((uint8_t **)parray, sizeof(struct s2n_array)));

    return 0;
}

int s2n_array_free(struct s2n_array *array)
{
    return s2n_array_free_p(&array);
}
