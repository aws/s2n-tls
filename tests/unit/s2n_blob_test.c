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

#include "s2n_test.h"

#include "utils/s2n_blob.h"
#include "utils/s2n_mem.h"

#include <s2n.h>

int main(int argc, char **argv)
{
    BEGIN_TEST();

    /* Null blob is not valid */
    EXPECT_FALSE(s2n_blob_is_valid(NULL));

    /* Invalid blob is not valid */
    struct s2n_blob b1 = {.data = 0, .size = 101 };
    EXPECT_FALSE(s2n_blob_is_valid(&b1));

    /* Size of 0 is OK if data is null */
    struct s2n_blob b2 = {.data = 0, .size = 0 };
    EXPECT_TRUE(s2n_blob_is_valid(&b2));

    /* Valid blob is valid */
    uint8_t array[12];
    struct s2n_blob b3 = {.data = array, .size = sizeof(array)};
    EXPECT_TRUE(s2n_blob_is_valid(&b3));

    /* Null blob is not growable */
    EXPECT_FALSE(s2n_blob_is_growable(NULL));
    EXPECT_FAILURE(s2n_realloc(NULL, 24));
    EXPECT_FAILURE(s2n_free(NULL));

    /* Static blob is not growable or freeable */
    struct s2n_blob g1;
    EXPECT_SUCCESS(s2n_blob_init(&g1, array, 12));
    EXPECT_FALSE(s2n_blob_is_growable(&g1));
    EXPECT_FAILURE(s2n_realloc(&g1, 24));
    EXPECT_FAILURE(s2n_free(&g1));

    /* Empty blob is freeable */
    struct s2n_blob g2 = {0};
    EXPECT_TRUE(s2n_blob_is_growable(&g2));
    EXPECT_SUCCESS(s2n_free(&g2));

    /* Empty blob is growable */
    struct s2n_blob g3 = {0};
    EXPECT_TRUE(s2n_blob_is_growable(&g3));
    EXPECT_SUCCESS(s2n_realloc(&g3,24));
    EXPECT_SUCCESS(s2n_free(&g3));

    /* Alloced blob can be freed */
    struct s2n_blob g4 = {0};
    EXPECT_SUCCESS(s2n_alloc(&g4, 12));
    EXPECT_TRUE(s2n_blob_is_growable(&g4));
    EXPECT_SUCCESS(s2n_free(&g4));

    /* Alloced blob can be realloced */
    struct s2n_blob g5 = {0};
    EXPECT_SUCCESS(s2n_alloc(&g5, 12));
    EXPECT_TRUE(s2n_blob_is_growable(&g5));
    EXPECT_SUCCESS(s2n_realloc(&g5, 24));
    EXPECT_SUCCESS(s2n_free(&g5));

    END_TEST();
}
