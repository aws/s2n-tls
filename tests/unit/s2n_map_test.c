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

#include "utils/s2n_map.h"

#include <string.h>

#include "api/s2n.h"
#include "s2n_test.h"

int main(int argc, char **argv)
{
    char keystr[sizeof("ffff")];
    char valstr[sizeof("16384")];
    struct s2n_map *empty, *map;
    struct s2n_blob key = { 0 };
    struct s2n_blob val = { 0 };
    bool key_found;

    BEGIN_TEST();
    EXPECT_SUCCESS(s2n_disable_tls13_in_test());

    EXPECT_NOT_NULL(empty = s2n_map_new());

    /* Try a lookup on an empty map. Expect an error because the map is still mutable. */
    EXPECT_SUCCESS(snprintf(keystr, sizeof(keystr), "%04x", 1234));
    key.data = (void *) keystr;
    key.size = strlen(keystr) + 1;
    EXPECT_ERROR(s2n_map_lookup(empty, &key, &val, &key_found));

    EXPECT_SUCCESS(snprintf(valstr, sizeof(valstr), "%05d", 1234));
    val.data = (void *) valstr;
    val.size = strlen(valstr) + 1;

    /* Try to add/put key with zero-size data. Expect failures */
    key.size = 0;
    EXPECT_ERROR(s2n_map_add(empty, &key, &val));
    EXPECT_ERROR(s2n_map_put(empty, &key, &val));
    key.size = strlen(keystr) + 1;

    /* Make the empty map complete */
    EXPECT_OK(s2n_map_complete(empty));

    /* Lookup and expect no result */
    EXPECT_OK(s2n_map_lookup(empty, &key, &val, &key_found));
    EXPECT_EQUAL(key_found, false);

    /* Done with the empty map */
    EXPECT_OK(s2n_map_free(empty));

    /* Expect failure since initial map size is zero */
    EXPECT_NULL(map = s2n_map_new_with_initial_capacity(0));

    /* Create map with the smallest initial size */
    EXPECT_NOT_NULL(map = s2n_map_new_with_initial_capacity(1));

    /* Insert 8k key value pairs of the form hex(i) -> dec(i) */
    for (int i = 0; i < 8192; i++) {
        EXPECT_SUCCESS(snprintf(keystr, sizeof(keystr), "%04x", i));
        EXPECT_SUCCESS(snprintf(valstr, sizeof(valstr), "%05d", i));

        key.data = (void *) keystr;
        key.size = strlen(keystr) + 1;
        val.data = (void *) valstr;
        val.size = strlen(valstr) + 1;

        EXPECT_OK(s2n_map_add(map, &key, &val));
    }

    /* Try adding some duplicates */
    for (int i = 0; i < 10; i++) {
        EXPECT_SUCCESS(snprintf(keystr, sizeof(keystr), "%04x", i));
        EXPECT_SUCCESS(snprintf(valstr, sizeof(valstr), "%05d", i));

        key.data = (void *) keystr;
        key.size = strlen(keystr) + 1;
        val.data = (void *) valstr;
        val.size = strlen(valstr) + 1;

        EXPECT_ERROR(s2n_map_add(map, &key, &val));
    }

    /* Try replacing some entries */
    for (int i = 0; i < 10; i++) {
        EXPECT_SUCCESS(snprintf(keystr, sizeof(keystr), "%04x", i));
        EXPECT_SUCCESS(snprintf(valstr, sizeof(valstr), "%05d", i + 1));

        key.data = (void *) keystr;
        key.size = strlen(keystr) + 1;
        val.data = (void *) valstr;
        val.size = strlen(valstr) + 1;

        EXPECT_OK(s2n_map_put(map, &key, &val));
    }

    /* Try a lookup before the map is complete: should fail */
    EXPECT_SUCCESS(snprintf(keystr, sizeof(keystr), "%04x", 1));
    EXPECT_ERROR(s2n_map_lookup(map, &key, &val, &key_found));

    /* Make the map complete */
    EXPECT_OK(s2n_map_complete(map));

    /* Make sure that add-after-complete fails */
    EXPECT_SUCCESS(snprintf(keystr, sizeof(keystr), "%04x", 8193));
    EXPECT_SUCCESS(snprintf(valstr, sizeof(valstr), "%05d", 8193));

    key.data = (void *) keystr;
    key.size = strlen(keystr) + 1;
    val.data = (void *) valstr;
    val.size = strlen(valstr) + 1;

    EXPECT_ERROR(s2n_map_add(map, &key, &val));

    /* Check for equivalence */
    for (int i = 0; i < 8192; i++) {
        if (i >= 10) {
            EXPECT_SUCCESS(snprintf(keystr, sizeof(keystr), "%04x", i));
            EXPECT_SUCCESS(snprintf(valstr, sizeof(valstr), "%05d", i));
        } else {
            /* The first 10 entries were overwritten with i+1 */
            EXPECT_SUCCESS(snprintf(keystr, sizeof(keystr), "%04x", i));
            EXPECT_SUCCESS(snprintf(valstr, sizeof(valstr), "%05d", i + 1));
        }

        key.data = (void *) keystr;
        key.size = strlen(keystr) + 1;

        EXPECT_OK(s2n_map_lookup(map, &key, &val, &key_found));
        EXPECT_EQUAL(key_found, true);

        EXPECT_SUCCESS(memcmp(val.data, valstr, strlen(valstr) + 1));
    }

    /* Check for a key that shouldn't be there */
    EXPECT_SUCCESS(snprintf(keystr, sizeof(keystr), "%04x", 8193));
    key.data = (void *) keystr;
    key.size = strlen(keystr) + 1;
    EXPECT_OK(s2n_map_lookup(map, &key, &val, &key_found));
    EXPECT_EQUAL(key_found, false);

    /* Make the map mutable */
    EXPECT_OK(s2n_map_unlock(map));
    /* Make sure that add-after-unlock succeeds */
    EXPECT_SUCCESS(snprintf(keystr, sizeof(keystr), "%04x", 8193));
    EXPECT_SUCCESS(snprintf(valstr, sizeof(valstr), "%05d", 8193));

    key.data = (void *) keystr;
    key.size = strlen(keystr) + 1;
    val.data = (void *) valstr;
    val.size = strlen(valstr) + 1;

    EXPECT_OK(s2n_map_add(map, &key, &val));

    /* Complete the map again */
    EXPECT_OK(s2n_map_complete(map));

    /* Check the element added after map unlock */
    EXPECT_OK(s2n_map_lookup(map, &key, &val, &key_found));
    EXPECT_EQUAL(key_found, true);
    EXPECT_SUCCESS(memcmp(val.data, valstr, strlen(valstr) + 1));

    EXPECT_OK(s2n_map_free(map));

    END_TEST();
}
