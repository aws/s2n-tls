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

#include "utils/s2n_safety.h"

static int failure_gte()
{
    gte_check(0, 1);

    return 0;
}

static int success_gte()
{
    gte_check(0, 0);
    gte_check(1, 0);

    return 0;
}

static int failure_gt()
{
    gt_check(0, 0);
    gt_check(0, 1);

    return 0;
}

static int success_gt()
{
    gt_check(1, 0);

    return 0;
}

static int failure_lte()
{
    lte_check(1, 0);

    return 0;
}

static int success_lte()
{
    lte_check(1, 1);
    lte_check(0, 1);

    return 0;
}

static int failure_lt()
{
    lt_check(1, 0);
    lt_check(1, 1);

    return 0;
}

static int success_lt()
{
    lt_check(0, 1);

    return 0;
}

static int success_notnull()
{
    notnull_check("");

    return 0;
}

static int failure_notnull()
{
    notnull_check(NULL);

    return 0;
}

static int success_memcpy()
{
    char dst[1024];
    char src[1024] = {0};

    memcpy_check(dst, src, 1024);

    return 0;
}

static int failure_memcpy()
{
    char src[1024];
    char *ptr = NULL;

    memcpy_check(ptr, src, 1024);

    return 0;
}

static int success_inclusive_range()
{
    inclusive_range_check(0, 0, 2);
    inclusive_range_check(0, 1, 2);
    inclusive_range_check(0, 2, 2);

    return 0;
}

static int failure_inclusive_range_too_high()
{
    inclusive_range_check(0, 3, 2);

    return 0;
}

static int failure_inclusive_range_too_low()
{
    inclusive_range_check(0, -1, 2);

    return 0;
}

static int success_exclusive_range()
{
    exclusive_range_check(0, 1, 2);

    return 0;
}

static int failure_exclusive_range_too_high()
{
    exclusive_range_check(0, 3, 2);

    return 0;
}

static int failure_exclusive_range_too_low()
{
    exclusive_range_check(0, -1, 2);

    return 0;
}

static int failure_exclusive_range_eq_high()
{
    exclusive_range_check(0, 2, 2);

    return 0;
}

static int failure_exclusive_range_eq_low()
{
    exclusive_range_check(0, 0, 2);

    return 0;
}

int main(int argc, char **argv)
{
    BEGIN_TEST();

    EXPECT_FAILURE(failure_gte());
    EXPECT_FAILURE(failure_lte());
    EXPECT_FAILURE(failure_gt());
    EXPECT_FAILURE(failure_lt());
    EXPECT_FAILURE(failure_notnull());
    EXPECT_FAILURE(failure_memcpy());
    EXPECT_FAILURE(failure_inclusive_range_too_high());
    EXPECT_FAILURE(failure_inclusive_range_too_low());
    EXPECT_FAILURE(failure_exclusive_range_too_high());
    EXPECT_FAILURE(failure_exclusive_range_too_low());
    EXPECT_FAILURE(failure_exclusive_range_eq_high());
    EXPECT_FAILURE(failure_exclusive_range_eq_low());

    EXPECT_SUCCESS(success_gte());
    EXPECT_SUCCESS(success_lte());
    EXPECT_SUCCESS(success_gt());
    EXPECT_SUCCESS(success_lt());
    EXPECT_SUCCESS(success_notnull());
    EXPECT_SUCCESS(success_memcpy());
    EXPECT_SUCCESS(success_inclusive_range());
    EXPECT_SUCCESS(success_exclusive_range());

    uint8_t a[4] = { 1, 2, 3, 4 };
    uint8_t b[4] = { 1, 2, 3, 4 };
    uint8_t c[4] = { 5, 6, 7, 8 };
    uint8_t d[4] = { 5, 6, 7, 8 };
    uint8_t e[4] = { 1, 2, 3, 4 };

    EXPECT_EQUAL(s2n_constant_time_equals(a, b, sizeof(a)), 1);
    EXPECT_EQUAL(s2n_constant_time_equals(a, c, sizeof(a)), 0);

    EXPECT_SUCCESS(s2n_constant_time_copy_or_dont(a, c, sizeof(a), 0));
    EXPECT_EQUAL(s2n_constant_time_equals(a, c, sizeof(a)), 1);

    for (int i = 1; i < 256; i++) {
        EXPECT_SUCCESS(s2n_constant_time_copy_or_dont(b, d, sizeof(a), i));
        EXPECT_EQUAL(s2n_constant_time_equals(b, d, sizeof(a)), 0);
        EXPECT_EQUAL(s2n_constant_time_equals(b, e, sizeof(a)), 1);
    }

    uint8_t x[1];
    uint8_t y[1];

    for (int i = 0; i < 256; i++) {
        for (int j = 0; j < 256; j++) {
           x[0] = i;
           y[0] = j;

           int expected = 0;

           if (i == j) {
                expected = 1;
           }

           EXPECT_EQUAL(s2n_constant_time_equals(x, y, sizeof(x)), expected);
        }
    }

    END_TEST();
}
