/*
 * Copyright 2016 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

#include <s2n.h>
#include <string.h>

#include "utils/s2n_map.h"

int main(int argc, char **argv)
{
    char keystr[sizeof("ffff")];
    char valstr[sizeof("16384")];
    struct s2n_map *map;

    BEGIN_TEST();

    EXPECT_NOT_NULL(map = s2n_map_new());

    /* Insert 64k key value pairs of the form hex(i) -> dec(i) */
    for (int i = 0; i < 16384; i++) {
        EXPECT_SUCCESS(snprintf(keystr, sizeof(keystr), "%04x", i));
        EXPECT_SUCCESS(snprintf(valstr, sizeof(valstr), "%05d", i));

        struct s2n_blob key = {.data = (uint8_t *) keystr, .size = strlen(keystr) + 1};
        struct s2n_blob val = {.data = (uint8_t *) valstr, .size = strlen(valstr) + 1};

        EXPECT_SUCCESS(s2n_map_add(map, &key, &val));
    }

    /* Try inserting some duplicates */
    for (int i = 0; i < 10; i++) {
        EXPECT_SUCCESS(snprintf(keystr, sizeof(keystr), "%04x", i));
        EXPECT_SUCCESS(snprintf(valstr, sizeof(valstr), "%05d", i));

        struct s2n_blob key = {.data = (uint8_t *) keystr, .size = strlen(keystr) + 1};
        struct s2n_blob val = {.data = (uint8_t *) valstr, .size = strlen(valstr) + 1};

        EXPECT_FAILURE(s2n_map_add(map, &key, &val));
    }

    /* Check for equivalence */
    for (int i = 0; i < 16384; i++) {

        EXPECT_SUCCESS(snprintf(keystr, sizeof(keystr), "%04x", i));
        EXPECT_SUCCESS(snprintf(valstr, sizeof(valstr), "%05d", i));

        struct s2n_blob key = {.data = (uint8_t *) keystr, .size = strlen(keystr) + 1};
        struct s2n_blob val;

        EXPECT_EQUAL(s2n_map_lookup(map, &key, &val), 1);

        EXPECT_SUCCESS(memcmp(val.data, valstr, strlen(valstr) + 1));
    }
       
        
    EXPECT_SUCCESS(snprintf(keystr, sizeof(keystr), "%04x", 16385));
    struct s2n_blob key = {.data = (uint8_t *) keystr, .size = strlen(keystr) + 1};
    struct s2n_blob val;
    EXPECT_EQUAL(s2n_map_lookup(map, &key, &val), 0);

    EXPECT_SUCCESS(s2n_map_free(map));

    END_TEST();
}
