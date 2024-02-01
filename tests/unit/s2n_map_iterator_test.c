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

#include "api/s2n.h"
#include "s2n_test.h"
#include "utils/s2n_map.h"
#include "utils/s2n_map_internal.h"

#define TEST_VALUE_COUNT 10

int main(int argc, char **argv)
{
    BEGIN_TEST();

    /* s2n_map_iterator iteration test */
    {
        struct s2n_map *map = s2n_map_new();
        EXPECT_NOT_NULL(map);
        /* fail to initialize an iterator on a mutable map */
        {
            struct s2n_map_iterator iter = { 0 };
            EXPECT_ERROR_WITH_ERRNO(s2n_map_iterator_init(&iter, map), S2N_ERR_MAP_MUTABLE);
        };

        EXPECT_OK(s2n_map_complete(map));

        /* has next is false on an empty map, and next returns an error */
        {
            struct s2n_map_iterator iter = { 0 };
            EXPECT_OK(s2n_map_iterator_init(&iter, map));

            EXPECT_FALSE(s2n_map_iterator_has_next(&iter));

            struct s2n_blob value = { 0 };
            EXPECT_ERROR_WITH_ERRNO(s2n_map_iterator_next(&iter, &value), S2N_ERR_ARRAY_INDEX_OOB);
        };

        EXPECT_OK(s2n_map_unlock(map));
        for (uint8_t i = 0; i < TEST_VALUE_COUNT; i++) {
            struct s2n_blob key = { .size = 1, .data = &i };
            struct s2n_blob val = { .size = 1, .data = &i };
            EXPECT_OK(s2n_map_put(map, &key, &val));
        }
        EXPECT_OK(s2n_map_complete(map));

        /* iterator goes over all elements */
        {
            bool seen[TEST_VALUE_COUNT] = { 0 };

            struct s2n_map_iterator iter = { 0 };
            EXPECT_OK(s2n_map_iterator_init(&iter, map));

            struct s2n_blob value = { 0 };
            for (size_t i = 0; i < TEST_VALUE_COUNT; i++) {
                EXPECT_TRUE(s2n_map_iterator_has_next(&iter));

                EXPECT_OK(s2n_map_iterator_next(&iter, &value));
                seen[*value.data] = true;
            }

            /* all elements have been iterated over */
            EXPECT_FALSE(s2n_map_iterator_has_next(&iter));
            EXPECT_ERROR_WITH_ERRNO(s2n_map_iterator_next(&iter, &value), S2N_ERR_ARRAY_INDEX_OOB);

            /* all elements were seen */
            for (size_t i = 0; i < TEST_VALUE_COUNT; i++) {
                EXPECT_TRUE(seen[i]);
            }
        };

        /* next returns an error when the blob is null */
        {
            struct s2n_map_iterator iter = { 0 };
            EXPECT_OK(s2n_map_iterator_init(&iter, map));

            EXPECT_ERROR_WITH_ERRNO(s2n_map_iterator_next(&iter, NULL), S2N_ERR_NULL);
        }

        EXPECT_OK(s2n_map_free(map));
    };

    /* test first and last slots in table */
    {
        /* 2 (first and last slot) * 2 (key and value) */
        struct s2n_blob blobs[2 * 2] = { 0 };
        for (uint8_t i = 0; i < (2 * 2); i++) {
            EXPECT_SUCCESS(s2n_alloc(&blobs[i], 1));
            *blobs[i].data = i;
        }

        struct s2n_map *test_map = s2n_map_new();
        EXPECT_NOT_NULL(test_map);

        /* set values in map to 0 and 1 */
        test_map->table[0].value = blobs[0];
        test_map->table[0].key = blobs[2];
        test_map->table[test_map->capacity - 1].value = blobs[1];
        test_map->table[test_map->capacity - 1].key = blobs[3];

        test_map->size = 2;
        EXPECT_OK(s2n_map_complete(test_map));

        struct s2n_map_iterator iter = { 0 };
        EXPECT_OK(s2n_map_iterator_init(&iter, test_map));
        bool seen[2] = { 0 };

        struct s2n_blob value = { 0 };
        for (size_t i = 0; i < 2; i++) {
            EXPECT_TRUE(s2n_map_iterator_has_next(&iter));

            EXPECT_OK(s2n_map_iterator_next(&iter, &value));
            seen[*value.data] = true;
        }

        /* assert that 0 and 1 were both seen */
        EXPECT_TRUE(seen[0] && seen[1]);

        EXPECT_OK(s2n_map_free(test_map));
    };

    END_TEST();
}
