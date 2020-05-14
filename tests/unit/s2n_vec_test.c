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
#include "s2n_test.h"
#include "utils/s2n_blob.h"
#include "utils/s2n_mem.h"
#include "utils/s2n_safety.h"
#include "utils/s2n_vec.h"

struct vec_element {
    int first;
    char second;
};

#define NUM_OF_ELEMENTS 17

int main(int argc, char **argv)
{
    struct s2n_vec *vec;
    int element_size = sizeof(struct vec_element);
    uint32_t len = 0;
    uint32_t capacity = 0;

    BEGIN_TEST();
    struct vec_element elements[NUM_OF_ELEMENTS] = {0};

    for (int i = 0; i < NUM_OF_ELEMENTS; i++) {
        elements[i].first = i;
        elements[i].second = 'a' + i;
    }

    /* Verify add and get elements with null vec */
    EXPECT_ERROR(s2n_vec_pushback(NULL, NULL));
    EXPECT_ERROR(s2n_vec_get(NULL, 0, NULL));

    /* Verify freeing null vec */
    EXPECT_ERROR(s2n_vec_free(NULL));

    EXPECT_NOT_NULL(vec = s2n_vec_new(element_size));

    /* Validate vec parameters */
    EXPECT_OK(s2n_vec_capacity(vec, &capacity));
    EXPECT_EQUAL(capacity, 16);
    EXPECT_OK(s2n_vec_len(vec, &len));
    EXPECT_EQUAL(len, 0);
    EXPECT_EQUAL(vec->element_size, element_size);

    /* Add an element */
    struct vec_element *element = NULL;
    EXPECT_OK(s2n_vec_pushback(vec, (void **)&element));
    EXPECT_NOT_NULL(element);
    element->first = elements[0].first;
    element->second = elements[0].second;

    /* Validate vec parameters */
    EXPECT_OK(s2n_vec_capacity(vec, &capacity));
    EXPECT_EQUAL(capacity, 16);
    EXPECT_OK(s2n_vec_len(vec, &len));
    EXPECT_EQUAL(len, 1);

    /* Get first element */
    struct vec_element *first_element = NULL;
    EXPECT_OK(s2n_vec_get(vec, 0, (void **)&first_element));
    EXPECT_NOT_NULL(first_element);
    EXPECT_EQUAL(first_element->first, elements[0].first);
    EXPECT_EQUAL(first_element->second, elements[0].second);

    /* Get second element */
    struct vec_element *second_element = NULL;
    EXPECT_ERROR(s2n_vec_get(vec, 1, (void **)&second_element));
    EXPECT_NULL(second_element);

    /* Add more than 16 elements */
    for (int i = 1; i < NUM_OF_ELEMENTS; i++) {
        struct vec_element *elem = NULL;
        EXPECT_OK(s2n_vec_pushback(vec, (void **)&elem));
        EXPECT_NOT_NULL(elem);
        elem->first = elements[i].first;
        elem->second = elements[i].second;
    }

    /* Validate vec parameters again */
    EXPECT_OK(s2n_vec_capacity(vec, &capacity));
    EXPECT_EQUAL(capacity, 32);
    EXPECT_OK(s2n_vec_len(vec, &len));
    EXPECT_EQUAL(len, 17);
    EXPECT_EQUAL(vec->element_size, element_size);
    EXPECT_SUCCESS(memcmp(vec->mem.data, elements, NUM_OF_ELEMENTS * element_size));

    /* Insert element at given index */
    struct vec_element *insert_element = NULL;
    EXPECT_OK(s2n_vec_insert(vec, 16, (void **)&insert_element));
    EXPECT_NOT_NULL(insert_element);
    insert_element->first = 20;
    insert_element->second = 'a' + 20;;

    /* Validate vec parameters */
    EXPECT_OK(s2n_vec_capacity(vec, &capacity));
    EXPECT_EQUAL(capacity, 32);
    EXPECT_OK(s2n_vec_len(vec, &len));
    EXPECT_EQUAL(len, 18);

    /* Get the inserted element */
    struct vec_element *inserted_element = NULL;
    EXPECT_OK(s2n_vec_get(vec, 16, (void **)&inserted_element));
    EXPECT_NOT_NULL(inserted_element);
    EXPECT_EQUAL(inserted_element->first, insert_element->first);
    EXPECT_EQUAL(inserted_element->second, insert_element->second);

    /* Get the element after the inserted element */
    struct vec_element *after_inserted_element = NULL;
    EXPECT_OK(s2n_vec_get(vec, 17, (void **)&after_inserted_element));
    EXPECT_NOT_NULL(after_inserted_element);
    EXPECT_EQUAL(after_inserted_element->first, elements[16].first);
    EXPECT_EQUAL(after_inserted_element->second, elements[16].second);

    /* Delete element from given index */
    EXPECT_OK(s2n_vec_remove(vec, 0));

    /* Validate vec parameters */
    EXPECT_OK(s2n_vec_capacity(vec, &capacity));
    EXPECT_EQUAL(capacity, 32);
    EXPECT_OK(s2n_vec_len(vec, &len));
    EXPECT_EQUAL(len, 17);

    /* Get the current element at the deleted index */
    struct vec_element *after_removed_element = NULL;
    EXPECT_OK(s2n_vec_get(vec, 0, (void **)&after_removed_element));
    EXPECT_EQUAL(after_removed_element->first, elements[1].first);
    EXPECT_EQUAL(after_removed_element->second, elements[1].second);

    /* Done with the vec, make sure it can be freed */
    EXPECT_OK(s2n_vec_free(vec));

    /* Check what happens if there is an integer overflow */
    /* 0xF00000F0 * 16 = 3840 (in 32 bit arithmatic) */
    EXPECT_NULL(vec = s2n_vec_new(0xF00000F0));
    EXPECT_NOT_NULL(vec = s2n_vec_new(240));
    EXPECT_OK(s2n_vec_free(vec));
    END_TEST();
}
