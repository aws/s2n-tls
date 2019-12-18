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
#include "utils/s2n_array.h"
#include "utils/s2n_blob.h"
#include "utils/s2n_mem.h"
#include "utils/s2n_safety.h"
#include "utils/s2n_set.h"

#define S2N_INITIAL_ARRAY_SIZE 16

/* Sets "out" to the index at which the element should be inserted.
 * Returns an error if the element already exists */
static int s2n_set_binary_search(struct s2n_set *set, void *element, uint32_t* out)
{
    notnull_check(set);
    notnull_check(element);
    notnull_check(out);
    struct s2n_array *array = set->data;
    int (*comparator)(const void*, const void*) = set->comparator;
    
    if (array->num_of_elements == 0) {
        *out = 0;
        return S2N_SUCCESS;
    }

    /* Use 64 bit ints to avoid possibility of overflow */
    int64_t low = 0;
    int64_t top = array->num_of_elements - 1;

    while (low <= top) {
        int64_t mid = low + ((top - low) / 2);
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

struct s2n_set *s2n_set_new(size_t element_size, int (*comparator)(const void*, const void*))
{
    notnull_check_ptr(comparator);
    struct s2n_blob mem = {0};
    GUARD_PTR(s2n_alloc(&mem, sizeof(struct s2n_set)));
    struct s2n_set *set = (void *) mem.data;
    *set = (struct s2n_set) {.data = s2n_array_new(element_size), .comparator = comparator};
    if(set->data == NULL) {
        s2n_free(&mem);
        return NULL;
    }
    return set;
}

int s2n_set_add(struct s2n_set *set, void *element)
{
    uint32_t index;
    GUARD(s2n_set_binary_search(set, element, &index));
    GUARD(s2n_array_insert_and_copy(set->data, element, index));
    return S2N_SUCCESS;
}

void *s2n_set_get(struct s2n_set *set, uint32_t index)
{
    return s2n_array_get(set->data, index);
}

int s2n_set_remove(struct s2n_set *set, uint32_t index)
{
    return s2n_array_remove(set->data, index);
}
    
int s2n_set_free_p(struct s2n_set **pset)
{
    notnull_check(pset);
    struct s2n_set *set = *pset;

    notnull_check(set);
    GUARD(s2n_array_free(set->data));
    GUARD(s2n_free_object((uint8_t **)pset, sizeof(struct s2n_set)));

    return S2N_SUCCESS;

}

int s2n_set_free(struct s2n_set *set)
{
    return s2n_set_free_p(&set);
}


int s2n_set_size(struct s2n_set *set)
{
    return set->data->num_of_elements;
}
