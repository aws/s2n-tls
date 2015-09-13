/*
 * Copyright 2014 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

#include <stdint.h>

#include <utils/s2n_safety.h>

#include "testlib/s2n_testlib.h"

uint8_t dst0[9];
const uint8_t src[9] = {1, 2, 3, 4, 5, 6, 7, 8, 9};

int main(int argc, char **argv)
{
    uint8_t dst1[9];

    BEGIN_TEST();

    EXPECT_SUCCESS(s2n_constant_time_copy_or_dont(dst1, src, 9, 0 /* do copy */));
    EXPECT_EQUAL(s2n_constant_time_equals(dst1, src, 9), 1);

    EXPECT_SUCCESS(s2n_constant_time_copy_or_dont(dst0, src, 9, 1 /* don't */));
    EXPECT_EQUAL(s2n_constant_time_equals(dst0, src, 9), 0);
    
    END_TEST();
}
