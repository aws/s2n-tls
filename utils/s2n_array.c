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
    size_t array_elements_size = array->element_size * array->num_of_elements;

    struct s2n_blob mem = {.data = array->elements, .size = array_elements_size, .allocated = array_elements_size};

    GUARD(s2n_realloc(&mem, array->element_size * capacity));

    /* Zero the extened part */
    memset_check(mem.data + array_elements_size, 0, mem.size - array_elements_size);

    /* Update array capacity and elements */
    array->capacity = capacity;
    array->elements = (void *) mem.data;

    return 0;
}

struct s2n_array *s2n_array_new(size_t element_size)
{
    struct s2n_blob mem = {0};
    struct s2n_array *array;

    GUARD_PTR(s2n_alloc(&mem, sizeof(struct s2n_array)));

    array = (void *) mem.data;
    array->capacity = 0;
    array->num_of_elements = 0;
    array->element_size = element_size;
    array->elements = NULL;

    GUARD_PTR(s2n_array_enlarge(array, S2N_INITIAL_ARRAY_SIZE));

    return array;
}

void *s2n_array_add(struct s2n_array *array)
{
    if (array == NULL) {
        return NULL;
    }

    if (array->num_of_elements >= array->capacity) {
        /* Enlarge the array */
        GUARD_PTR(s2n_array_enlarge(array, array->capacity * 2));
    }

    void *element = (uint8_t *) array->elements + array->element_size * array->num_of_elements;
    array->num_of_elements++;

    return element;
}

void *s2n_array_get(struct s2n_array *array, uint32_t index)
{
    if (array == NULL) {
        return NULL;
    }

    void *element = NULL;

    if (index < array->num_of_elements) {
        element = (uint8_t *) array->elements + array->element_size * index;
    }

    return element;
}

void *s2n_array_insert(struct s2n_array *array, uint32_t index)
{
    if (array == NULL) {
        return NULL;
    }

    if (array->num_of_elements >= array->capacity) {
        /* Enlarge the array */
        GUARD_PTR(s2n_array_enlarge(array, array->capacity * 2));
    }

    memmove((uint8_t *) array->elements + array->element_size * (index + 1),
            (uint8_t *) array->elements + array->element_size * index,
            (array->num_of_elements - index) * array->element_size);

    void *element = (uint8_t *) array->elements + array->element_size * index;
    array->num_of_elements++;

    return element;
}

int s2n_array_remove(struct s2n_array *array, uint32_t index)
{
    notnull_check(array);

    memmove((uint8_t *) array->elements + array->element_size * index,
            (uint8_t *) array->elements + array->element_size * (index + 1),
            (array->num_of_elements - index - 1) * array->element_size);

    array->num_of_elements--;

    /* After shifting, zero the last element */
    memset_check((uint8_t *) array->elements + array->element_size * array->num_of_elements,
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
    GUARD(s2n_free_object((uint8_t **)&array->elements, array->capacity * array->element_size));

    /* And finally the array */
    GUARD(s2n_free_object((uint8_t **)parray, sizeof(struct s2n_array)));

    return 0;
}

int s2n_array_free(struct s2n_array *array)
{
    return s2n_array_free_p(&array);
}

int s2n_array_binary_search(int low, int top, struct s2n_array *array, void *element,
                            int (*comparator)(void*, void*))
{
    notnull_check(array);
    notnull_check(element);

    while (low <= top) {
        int mid = low + ((top - low) / 2);
        int m = comparator(s2n_array_get(array, mid), element);

        if (m == 0) {
            /* Return -1 when a match is found */
            return -1;
        } else if (m > 0) {
            top = mid - 1;
        } else if (m < 0) {
            low = mid + 1;
        }
    }

    /* Return the index at which element is to be inserted */
    return low;
}
