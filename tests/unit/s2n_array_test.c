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
#include "utils/s2n_array.h"

#include "s2n_test.h"
#include "utils/s2n_blob.h"
#include "utils/s2n_mem.h"
#include "utils/s2n_safety.h"

struct array_element {
    int first;
    char second;
};

#define NUM_OF_ELEMENTS 17

int main(int argc, char **argv)
{
    BEGIN_TEST();
    EXPECT_SUCCESS(s2n_disable_tls13_in_test());

    size_t element_size = sizeof(struct array_element);

    struct array_element elements[NUM_OF_ELEMENTS] = { 0 };
    for (size_t i = 0; i < NUM_OF_ELEMENTS; i++) {
        elements[i].first = i;
        elements[i].second = 'a' + i;
    }

    {
        struct s2n_array *array = { 0 };
        uint32_t len = 0;
        uint32_t capacity = 0;

        /* Verify add and get elements with null array */
        EXPECT_ERROR(s2n_array_pushback(NULL, NULL));
        EXPECT_ERROR(s2n_array_get(NULL, 0, NULL));

        /* Verify freeing null array */
        EXPECT_ERROR(s2n_array_free(NULL));

        EXPECT_NOT_NULL(array = s2n_array_new(element_size));

        /* Validate array parameters */
        EXPECT_OK(s2n_array_capacity(array, &capacity));
        EXPECT_EQUAL(capacity, 16);
        EXPECT_OK(s2n_array_num_elements(array, &len));
        EXPECT_EQUAL(len, 0);
        EXPECT_EQUAL(array->element_size, element_size);

        /* Add an element */
        struct array_element *element = NULL;
        EXPECT_OK(s2n_array_pushback(array, (void **) &element));
        EXPECT_NOT_NULL(element);
        element->first = elements[0].first;
        element->second = elements[0].second;

        /* Validate array parameters */
        EXPECT_OK(s2n_array_capacity(array, &capacity));
        EXPECT_EQUAL(capacity, 16);
        EXPECT_OK(s2n_array_num_elements(array, &len));
        EXPECT_EQUAL(len, 1);

        /* Get first element */
        struct array_element *first_element = NULL;
        EXPECT_OK(s2n_array_get(array, 0, (void **) &first_element));
        EXPECT_NOT_NULL(first_element);
        EXPECT_EQUAL(first_element->first, elements[0].first);
        EXPECT_EQUAL(first_element->second, elements[0].second);

        /* Get second element */
        struct array_element *second_element = NULL;
        EXPECT_ERROR(s2n_array_get(array, 1, (void **) &second_element));
        EXPECT_NULL(second_element);

        /* Add more than 16 elements */
        for (int i = 1; i < NUM_OF_ELEMENTS; i++) {
            struct array_element *elem = NULL;
            EXPECT_OK(s2n_array_pushback(array, (void **) &elem));
            EXPECT_NOT_NULL(elem);
            elem->first = elements[i].first;
            elem->second = elements[i].second;
        }

        /* Validate array parameters again */
        EXPECT_OK(s2n_array_capacity(array, &capacity));
        EXPECT_EQUAL(capacity, 32);
        EXPECT_OK(s2n_array_num_elements(array, &len));
        EXPECT_EQUAL(len, 17);
        EXPECT_EQUAL(array->element_size, element_size);
        EXPECT_SUCCESS(memcmp(array->mem.data, elements, NUM_OF_ELEMENTS * element_size));

        /* Insert element at given index */
        struct array_element *insert_element = NULL;
        EXPECT_OK(s2n_array_insert(array, 16, (void **) &insert_element));
        EXPECT_NOT_NULL(insert_element);
        insert_element->first = 20;
        insert_element->second = 'a' + 20;

        /* Validate array parameters */
        EXPECT_OK(s2n_array_capacity(array, &capacity));
        EXPECT_EQUAL(capacity, 32);
        EXPECT_OK(s2n_array_num_elements(array, &len));
        EXPECT_EQUAL(len, 18);

        /* Get the inserted element */
        struct array_element *inserted_element = NULL;
        EXPECT_OK(s2n_array_get(array, 16, (void **) &inserted_element));
        EXPECT_NOT_NULL(inserted_element);
        EXPECT_EQUAL(inserted_element->first, insert_element->first);
        EXPECT_EQUAL(inserted_element->second, insert_element->second);

        /* Get the element after the inserted element */
        struct array_element *after_inserted_element = NULL;
        EXPECT_OK(s2n_array_get(array, 17, (void **) &after_inserted_element));
        EXPECT_NOT_NULL(after_inserted_element);
        EXPECT_EQUAL(after_inserted_element->first, elements[16].first);
        EXPECT_EQUAL(after_inserted_element->second, elements[16].second);

        /* Delete element from given index */
        EXPECT_OK(s2n_array_remove(array, 0));

        /* Validate array parameters */
        EXPECT_OK(s2n_array_capacity(array, &capacity));
        EXPECT_EQUAL(capacity, 32);
        EXPECT_OK(s2n_array_num_elements(array, &len));
        EXPECT_EQUAL(len, 17);

        /* Get the current element at the deleted index */
        struct array_element *after_removed_element = NULL;
        EXPECT_OK(s2n_array_get(array, 0, (void **) &after_removed_element));
        EXPECT_EQUAL(after_removed_element->first, elements[1].first);
        EXPECT_EQUAL(after_removed_element->second, elements[1].second);

        /* Done with the array, make sure it can be freed */
        EXPECT_OK(s2n_array_free(array));

        /* Check what happens if there is an integer overflow */
        /* 0xF00000F0 * 16 = 3840 (in 32 bit arithmatic) */
        EXPECT_NULL(array = s2n_array_new(0xF00000F0));
        EXPECT_NOT_NULL(array = s2n_array_new(240));
        EXPECT_OK(s2n_array_free(array));
    }

    /* Arrays initialize with default capacity */
    {
        DEFER_CLEANUP(struct s2n_array *default_array = s2n_array_new(element_size), s2n_array_free_p);

        uint32_t capacity = 0;
        EXPECT_OK(s2n_array_capacity(default_array, &capacity));
        EXPECT_EQUAL(capacity, S2N_INITIAL_ARRAY_SIZE);
    }

    /* Test creating arrays with different initial capacities */
    for (int i = 0; i < 10; i++) {
        uint32_t capacity_set = i * i;
        DEFER_CLEANUP(struct s2n_array *array = s2n_array_new_with_capacity(element_size, capacity_set),
                s2n_array_free_p);

        uint32_t actual_capacity = 0;
        EXPECT_OK(s2n_array_capacity(array, &actual_capacity));
        EXPECT_EQUAL(capacity_set, actual_capacity);

        /* Array doesn't grow before capacity is reached */
        for (int j = 0; j < capacity_set; j++) {
            struct array_element *element = NULL;
            EXPECT_OK(s2n_array_pushback(array, (void **) &element));
            EXPECT_NOT_NULL(element);

            EXPECT_OK(s2n_array_capacity(array, &actual_capacity));
            EXPECT_EQUAL(capacity_set, actual_capacity);

            uint32_t len = 0;
            EXPECT_OK(s2n_array_num_elements(array, &len));
            EXPECT_EQUAL(len, j + 1);
        }

        /* Array grows only after capacity is reached */
        struct array_element *element = NULL;
        EXPECT_OK(s2n_array_pushback(array, (void **) &element));
        EXPECT_NOT_NULL(element);

        EXPECT_OK(s2n_array_capacity(array, &actual_capacity));
        EXPECT_NOT_EQUAL(capacity_set, actual_capacity);

        uint32_t len = 0;
        EXPECT_OK(s2n_array_num_elements(array, &len));
        EXPECT_EQUAL(len, capacity_set + 1);
    }

    END_TEST();
}
