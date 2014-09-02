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

static int failure_gte(const char **err)
{
    gte_check(0, 1);

    return 0;
}

static int success_gte(const char **err)
{
    gte_check(0, 0);
    gte_check(1, 0);

    return 0;
}

static int failure_gt(const char **err)
{
    gt_check(0, 0);
    gt_check(0, 1);

    return 0;
}

static int success_gt(const char **err)
{
    gt_check(1, 0);

    return 0;
}

static int failure_lte(const char **err)
{
    lte_check(1, 0);

    return 0;
}

static int success_lte(const char **err)
{
    lte_check(1, 1);
    lte_check(0, 1);

    return 0;
}

static int failure_lt(const char **err)
{
    lt_check(1, 0);
    lt_check(1, 1);

    return 0;
}

static int success_lt(const char **err)
{
    lt_check(0, 1);

    return 0;
}

static int success_notnull(const char **err)
{
    notnull_check("");

    return 0;
}

static int failure_notnull(const char **err)
{
    notnull_check(NULL);

    return 0;
}

static int success_memcpy(const char **err)
{
    char dst[1024];
    char src[1024];

    memcpy_check(dst, src, 1024);

    return 0;
}

static int failure_memcpy(const char **err)
{
    char src[1024];
    char *ptr = NULL;

    memcpy_check(ptr, src, 1024);

    return 0;
}

static int success_inclusive_range(const char **err)
{
    inclusive_range_check(0, 0, 2);
    inclusive_range_check(0, 1, 2);
    inclusive_range_check(0, 2, 2);

    return 0;
}

static int failure_inclusive_range_too_high(const char **err)
{
    inclusive_range_check(0, 3, 2);

    return 0;
}

static int failure_inclusive_range_too_low(const char **err)
{
    inclusive_range_check(0, -1, 2);

    return 0;
}

static int success_exclusive_range(const char **err)
{
    exclusive_range_check(0, 1, 2);

    return 0;
}

static int failure_exclusive_range_too_high(const char **err)
{
    exclusive_range_check(0, 3, 2);

    return 0;
}

static int failure_exclusive_range_too_low(const char **err)
{
    exclusive_range_check(0, -1, 2);

    return 0;
}

static int failure_exclusive_range_eq_high(const char **err)
{
    exclusive_range_check(0, 2, 2);

    return 0;
}

static int failure_exclusive_range_eq_low(const char **err)
{
    exclusive_range_check(0, 0, 2);

    return 0;
}

int main(int argc, char **argv)
{
    BEGIN_TEST();

    EXPECT_FAILURE(failure_gte(&err));
    EXPECT_FAILURE(failure_lte(&err));
    EXPECT_FAILURE(failure_gt(&err));
    EXPECT_FAILURE(failure_lt(&err));
    EXPECT_FAILURE(failure_notnull(&err));
    EXPECT_FAILURE(failure_memcpy(&err));
    EXPECT_FAILURE(failure_inclusive_range_too_high(&err));
    EXPECT_FAILURE(failure_inclusive_range_too_low(&err));
    EXPECT_FAILURE(failure_exclusive_range_too_high(&err));
    EXPECT_FAILURE(failure_exclusive_range_too_low(&err));
    EXPECT_FAILURE(failure_exclusive_range_eq_high(&err));
    EXPECT_FAILURE(failure_exclusive_range_eq_low(&err));

    EXPECT_SUCCESS(success_gte(&err));
    EXPECT_SUCCESS(success_lte(&err));
    EXPECT_SUCCESS(success_gt(&err));
    EXPECT_SUCCESS(success_lt(&err));
    EXPECT_SUCCESS(success_notnull(&err));
    EXPECT_SUCCESS(success_memcpy(&err));
    EXPECT_SUCCESS(success_inclusive_range(&err));
    EXPECT_SUCCESS(success_exclusive_range(&err));

    END_TEST();
}
