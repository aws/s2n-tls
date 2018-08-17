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

int s2n_array_free(struct s2n_array *array)
{
    notnull_check(array);
    struct s2n_blob mem = {0};

    /* Free the elements */
    mem.data = (void *) array->elements;
    mem.size = array->capacity * array->element_size;
    GUARD(s2n_free(&mem));

    /* And finally the array */
    mem.data = (void *) array;
    mem.size = sizeof(struct s2n_array);
    GUARD(s2n_free(&mem));

    return 0;
}
