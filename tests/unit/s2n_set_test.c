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
#include "utils/s2n_set.h"

#include "s2n_test.h"
#include "utils/s2n_blob.h"
#include "utils/s2n_mem.h"
#include "utils/s2n_safety.h"

struct array_element {
    int first;
    char second;
};

static int s2n_binary_search_comparator(const void *pa, const void *pb)
{
    const struct array_element *a = (const struct array_element *) pa;
    const struct array_element *b = (const struct array_element *) pb;

    if (a->first > b->first) {
        return 1;
    } else if (a->first < b->first) {
        return -1;
    } else {
        return 0;
    }
}

int main(int argc, char **argv)
{
    const int element_size = sizeof(struct array_element);
    uint32_t set_len = 0;
    struct array_element *ep = NULL;

    BEGIN_TEST();
    EXPECT_SUCCESS(s2n_disable_tls13_in_test());
    EXPECT_NULL(s2n_set_new(element_size, NULL));

    struct s2n_set *set = NULL;
    EXPECT_NOT_NULL(set = s2n_set_new(element_size, s2n_binary_search_comparator));
    EXPECT_OK(s2n_set_len(set, &set_len));
    EXPECT_EQUAL(set_len, 0);
    EXPECT_ERROR(s2n_set_remove(set, 0));

    struct array_element e1 = { .first = 1, .second = 'a' };
    EXPECT_OK(s2n_set_add(set, &e1));
    EXPECT_OK(s2n_set_len(set, &set_len));
    EXPECT_EQUAL(set_len, 1);
    EXPECT_OK(s2n_set_get(set, 0, (void **) &ep));
    EXPECT_NOT_NULL(ep);
    EXPECT_EQUAL(ep->first, 1);
    EXPECT_EQUAL(ep->second, 'a');
    EXPECT_ERROR(s2n_set_get(set, 1, (void **) &ep));

    /* Insert an element that will go after */
    struct array_element e2 = { .first = 10, .second = 'b' };
    EXPECT_OK(s2n_set_add(set, &e2));
    EXPECT_OK(s2n_set_len(set, &set_len));
    EXPECT_EQUAL(set_len, 2);
    EXPECT_OK(s2n_set_get(set, 0, (void **) &ep));
    EXPECT_EQUAL(ep->first, 1);
    EXPECT_EQUAL(ep->second, 'a');
    EXPECT_OK(s2n_set_get(set, 1, (void **) &ep));
    EXPECT_EQUAL(ep->first, 10);
    EXPECT_EQUAL(ep->second, 'b');
    EXPECT_ERROR(s2n_set_get(set, 2, (void **) &ep));

    /* insert an element to the middle */
    struct array_element e3 = { .first = 5, .second = 'c' };
    EXPECT_OK(s2n_set_add(set, &e3));
    EXPECT_OK(s2n_set_len(set, &set_len));
    EXPECT_EQUAL(set_len, 3);
    EXPECT_OK(s2n_set_get(set, 0, (void **) &ep));
    EXPECT_EQUAL(ep->first, 1);
    EXPECT_EQUAL(ep->second, 'a');
    EXPECT_OK(s2n_set_get(set, 1, (void **) &ep));
    EXPECT_EQUAL(ep->first, 5);
    EXPECT_EQUAL(ep->second, 'c');
    EXPECT_OK(s2n_set_get(set, 2, (void **) &ep));
    EXPECT_EQUAL(ep->first, 10);
    EXPECT_EQUAL(ep->second, 'b');
    EXPECT_ERROR(s2n_set_get(set, 3, (void **) &ep));

    /* insert an element at the front */
    struct array_element e4 = { .first = 0, .second = 'd' };
    EXPECT_OK(s2n_set_add(set, &e4));
    EXPECT_OK(s2n_set_len(set, &set_len));
    EXPECT_EQUAL(set_len, 4);
    EXPECT_OK(s2n_set_get(set, 0, (void **) &ep));
    EXPECT_EQUAL(ep->first, 0);
    EXPECT_EQUAL(ep->second, 'd');
    EXPECT_OK(s2n_set_get(set, 1, (void **) &ep));
    EXPECT_EQUAL(ep->first, 1);
    EXPECT_EQUAL(ep->second, 'a');
    EXPECT_OK(s2n_set_get(set, 2, (void **) &ep));
    EXPECT_EQUAL(ep->first, 5);
    EXPECT_EQUAL(ep->second, 'c');
    EXPECT_OK(s2n_set_get(set, 3, (void **) &ep));
    EXPECT_EQUAL(ep->first, 10);
    EXPECT_EQUAL(ep->second, 'b');
    EXPECT_ERROR(s2n_set_get(set, 4, (void **) &ep));

    /* Try removing non-existent elements */
    EXPECT_ERROR(s2n_set_remove(set, 4));
    EXPECT_OK(s2n_set_len(set, &set_len));
    EXPECT_EQUAL(set_len, 4);
    EXPECT_OK(s2n_set_get(set, 0, (void **) &ep));
    EXPECT_EQUAL(ep->first, 0);
    EXPECT_EQUAL(ep->second, 'd');
    EXPECT_OK(s2n_set_get(set, 1, (void **) &ep));
    EXPECT_EQUAL(ep->first, 1);
    EXPECT_EQUAL(ep->second, 'a');
    EXPECT_OK(s2n_set_get(set, 2, (void **) &ep));
    EXPECT_EQUAL(ep->first, 5);
    EXPECT_EQUAL(ep->second, 'c');
    EXPECT_OK(s2n_set_get(set, 3, (void **) &ep));
    EXPECT_EQUAL(ep->first, 10);
    EXPECT_EQUAL(ep->second, 'b');
    EXPECT_ERROR(s2n_set_get(set, 4, (void **) &ep));

    /* Successfully remove an element */
    EXPECT_OK(s2n_set_remove(set, 1));
    EXPECT_OK(s2n_set_len(set, &set_len));
    EXPECT_EQUAL(set_len, 3);
    EXPECT_OK(s2n_set_get(set, 0, (void **) &ep));
    EXPECT_EQUAL(ep->first, 0);
    EXPECT_EQUAL(ep->second, 'd');
    EXPECT_OK(s2n_set_get(set, 1, (void **) &ep));
    EXPECT_EQUAL(ep->first, 5);
    EXPECT_EQUAL(ep->second, 'c');
    EXPECT_OK(s2n_set_get(set, 2, (void **) &ep));
    EXPECT_EQUAL(ep->first, 10);
    EXPECT_EQUAL(ep->second, 'b');
    EXPECT_ERROR(s2n_set_get(set, 3, (void **) &ep));

    /* insert an element that already exists */
    struct array_element e5 = { .first = 5, .second = 'e' };
    EXPECT_ERROR(s2n_set_add(set, &e5));
    EXPECT_OK(s2n_set_len(set, &set_len));
    EXPECT_EQUAL(set_len, 3);
    EXPECT_OK(s2n_set_get(set, 0, (void **) &ep));
    EXPECT_EQUAL(ep->first, 0);
    EXPECT_EQUAL(ep->second, 'd');
    EXPECT_OK(s2n_set_get(set, 1, (void **) &ep));
    EXPECT_EQUAL(ep->first, 5);
    EXPECT_EQUAL(ep->second, 'c');
    EXPECT_OK(s2n_set_get(set, 2, (void **) &ep));
    EXPECT_EQUAL(ep->first, 10);
    EXPECT_EQUAL(ep->second, 'b');
    EXPECT_ERROR(s2n_set_get(set, 3, (void **) &ep));

    /* Free the set to avoid memory leak */
    EXPECT_OK(s2n_set_free(set));

    /* Check what happens if there is an integer overflow */
    /* 0xF00000F0 * 16 = 3840 (in 32 bit arithmatic) */
    EXPECT_NULL(s2n_set_new(0xF00000F0, s2n_binary_search_comparator));
    EXPECT_NOT_NULL(set = s2n_set_new(240, s2n_binary_search_comparator));
    EXPECT_OK(s2n_set_free(set));
    END_TEST();
}
