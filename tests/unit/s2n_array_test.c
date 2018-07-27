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
#include "s2n_test.h"
#include "utils/s2n_blob.h"
#include "utils/s2n_mem.h"
#include "utils/s2n_safety.h"
#include "utils/s2n_array.h"

int main(int argc, char **argv)
{
    struct array_element {
        int first;
        char second;
    };

    struct s2n_array *array;
    int num_of_elements = 17;
    int element_size = sizeof(struct array_element);

    BEGIN_TEST();

    struct s2n_blob mem;
    GUARD(s2n_alloc(&mem, sizeof(struct array_element) * num_of_elements));
    GUARD(s2n_blob_zero(&mem));

    struct array_element *elements = (struct  array_element *) (void *) mem.data;

    for (int i = 0; i < num_of_elements; i++) {
        elements[i].first = i;
        elements[i].second = 'a' + i;
    }

    /* Verify add and get elements with null array */
    EXPECT_NULL(s2n_array_add(NULL));
    EXPECT_NULL(s2n_array_get(NULL, 0));

    /* Verify freeing null array */
    EXPECT_FAILURE(s2n_array_free(NULL));

    EXPECT_NOT_NULL(array = s2n_array_new(element_size));

    /* Validate array parameters */
    EXPECT_EQUAL(array->capacity, 16);
    EXPECT_EQUAL(array->num_of_elements, 0);
    EXPECT_EQUAL(array->element_size, element_size);

    /* Add an element */
    struct array_element *element = s2n_array_add(array);
    element->first = elements[0].first;
    element->second = elements[0].second;

    /* Validate array parameters */
    EXPECT_EQUAL(array->capacity, 16);
    EXPECT_EQUAL(array->num_of_elements, 1);

    /* Get first element */
    struct array_element *first_element = s2n_array_get(array, 0);
    EXPECT_EQUAL(first_element->first, elements[0].first);
    EXPECT_EQUAL(first_element->second, elements[0].second);

    /* Get second element */
    struct array_element *second_element = s2n_array_get(array, 1);
    EXPECT_NULL(second_element);

    /* Add more than 16 elements */
    for (int i = 1; i < num_of_elements; i++) {
        struct array_element *elem = s2n_array_add(array);
        elem->first = elements[i].first;
        elem->second = elements[i].second;
    }

    /* Validate array parameters again */
    EXPECT_EQUAL(array->capacity, 32);
    EXPECT_EQUAL(array->num_of_elements, 17);
    EXPECT_EQUAL(array->element_size, element_size);
    EXPECT_SUCCESS(memcmp(array->elements, mem.data, num_of_elements * element_size));

    /* Insert element at given index */
    struct array_element *insert_element = s2n_array_insert(array, 16);
    insert_element->first = 20;
    insert_element->second = 'a' + 20;;

    /* Validate array parameters */
    EXPECT_EQUAL(array->capacity, 32);
    EXPECT_EQUAL(array->num_of_elements, 18);

    /* Get the inserted element */
    struct array_element *inserted_element = s2n_array_get(array, 16);
    EXPECT_EQUAL(inserted_element->first, insert_element->first);
    EXPECT_EQUAL(inserted_element->second, insert_element->second);

    /* Get the element after the inserted element */
    struct array_element *after_inserted_element = s2n_array_get(array, 17);
    EXPECT_EQUAL(after_inserted_element->first, elements[16].first);
    EXPECT_EQUAL(after_inserted_element->second, elements[16].second);

    /* Delete element from given index */
    EXPECT_SUCCESS(s2n_array_remove(array, 0));

    /* Validate array parameters */
    EXPECT_EQUAL(array->capacity, 32);
    EXPECT_EQUAL(array->num_of_elements, 17);

    /* Get the current element at the deleted index */
    struct array_element *after_removed_element = s2n_array_get(array, 0);
    EXPECT_EQUAL(after_removed_element->first, elements[1].first);
    EXPECT_EQUAL(after_removed_element->second, elements[1].second);

    /* Done with the array, make sure it can be freed */
    EXPECT_SUCCESS(s2n_array_free(array));

    EXPECT_SUCCESS(s2n_free(&mem));

    END_TEST();
}
