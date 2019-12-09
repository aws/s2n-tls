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

    END_TEST();
}
