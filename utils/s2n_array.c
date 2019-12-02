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

    struct s2n_array initilizer = {.mem = {0}, .num_of_elements = 0, .capacity = 0, .element_size = element_size};
    struct s2n_array *array = (void *) mem.data;
    *array = initilizer;
    GUARD_PTR(s2n_array_enlarge(array, S2N_INITIAL_ARRAY_SIZE));

    return array;
}

void *s2n_array_add(struct s2n_array *array)
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

/* Sets "out" to the index at which the element should be inserted.
 * Returns an error if the element already exists */
int s2n_array_binary_search(struct s2n_array *array, void *element, int (*comparator)(void*, void*), uint32_t* out)
{
    notnull_check(array);
    notnull_check(element);
    notnull_check(out);
    if (array->num_of_elements == 0) {
        *out = 0;
        return S2N_SUCCESS;
    }

    if (array->num_of_elements == 1) {
        void* array_element = NULL;
        GUARD_NONNULL(array_element = s2n_array_get(array, 0));
        int m = comparator(array_element, element);
        S2N_ERROR_IF(m == 0, S2N_ELEMENT_ALREADY_IN_ARRAY);
        if (m > 0) {
            *out = 0;
        } else {
            *out = 1;
        }
        return S2N_SUCCESS;
    }

    uint32_t low = 0;
    uint32_t top = array->num_of_elements - 1;

    while (low <= top) {
        int mid = low + ((top - low) / 2);
        void* array_element = NULL;
        GUARD_NONNULL(array_element = s2n_array_get(array, mid));
        int m = comparator(array_element, element);

        S2N_ERROR_IF(m == 0, S2N_ELEMENT_ALREADY_IN_ARRAY);
        if (m > 0) {
            top = mid - 1;
        } else {
            low = mid + 1;
        }
    }

    *out = low;
    return S2N_SUCCESS;
}

void *s2n_array_insert_sorted(struct s2n_array *array, void *element, int (*comparator)(void*, void*))
{
    uint32_t index;
    GUARD_PTR(s2n_array_binary_search(array, element, comparator, &index));
    return s2n_array_insert(array, index);
}
