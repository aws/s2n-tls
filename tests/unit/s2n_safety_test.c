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

#define CHECK_OVF_0(fn, type, a, b)             \
  do {                                          \
    type result_val;                            \
    EXPECT_FAILURE(fn((a), (b), &result_val));  \
  } while (0)


#define CHECK_OVF(fn, type, a, b)               \
  do {                                          \
    CHECK_OVF_0(fn, type, a, b);                \
    CHECK_OVF_0(fn, type, b, a);                \
  } while (0)

#define CHECK_NO_OVF_0(fn, type, a, b, r)       \
  do {                                          \
    type result_val;                            \
    EXPECT_SUCCESS(fn((a), (b), &result_val));  \
    EXPECT_EQUAL(result_val,(r));               \
  } while (0)

#define CHECK_NO_OVF(fn, type, a, b, r)         \
  do {                                          \
    CHECK_NO_OVF_0(fn, type, a, b, r);          \
    CHECK_NO_OVF_0(fn, type, b, a, r);          \
  } while (0)


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

static int success_ct_pkcs1()
{
    uint8_t pkcs1_data[] = { 0x00, 0x02, 0x80, 0x08, 0x0c, 0x00, 0xab, 0xcd, 0xef, 0x00 };
    uint8_t outbuf[] = { 0x11, 0x22, 0x33, 0x44 };
    uint8_t expected[] = { 0xab, 0xcd, 0xef, 0x00 };

    s2n_constant_time_pkcs1_unpad_or_dont(outbuf, pkcs1_data, sizeof(pkcs1_data), sizeof(outbuf));

    return memcmp(outbuf, expected, sizeof(expected)) ? -1 : 0;
}

static int success_ct_pkcs1_negative()
{
    uint8_t pkcs1_data_too_long[] = { 0x00, 0x02, 0x80, 0x0f, 0x00, 0x10, 0xab, 0xcd, 0xef, 0x00 };
    uint8_t outbuf[] = { 0x11, 0x22, 0x33, 0x44 };
    uint8_t expected[] = { 0x11, 0x22, 0x33, 0x44 };

    s2n_constant_time_pkcs1_unpad_or_dont(outbuf, pkcs1_data_too_long, sizeof(pkcs1_data_too_long), sizeof(outbuf));
    if (memcmp(outbuf, expected, sizeof(expected))) {
        return -1;
    }

    uint8_t pkcs1_data_too_short[] = { 0x00, 0x02, 0x80, 0x01, 0x02, 0x07, 0x00, 0xcd, 0xef, 0x00 };

    s2n_constant_time_pkcs1_unpad_or_dont(outbuf, pkcs1_data_too_short, sizeof(pkcs1_data_too_short), sizeof(outbuf));
    if (memcmp(outbuf, expected, sizeof(expected))) {
        return -1;
    }

    uint8_t pkcs1_data_zeroes_in_pad[] = { 0x00, 0x02, 0x80, 0x00, 0x0c, 0x00, 0xab, 0xcd, 0xef, 0x00 };
    s2n_constant_time_pkcs1_unpad_or_dont(outbuf, pkcs1_data_zeroes_in_pad, sizeof(pkcs1_data_zeroes_in_pad), sizeof(outbuf));
    if (memcmp(outbuf, expected, sizeof(expected))) {
        return -1;
    }

    uint8_t pkcs1_data_zeroes_in_pad2[] = { 0x00, 0x02, 0x80, 0x11, 0x00, 0x00, 0xab, 0xcd, 0xef, 0x00 };
    s2n_constant_time_pkcs1_unpad_or_dont(outbuf, pkcs1_data_zeroes_in_pad2, sizeof(pkcs1_data_zeroes_in_pad2), sizeof(outbuf));
    if (memcmp(outbuf, expected, sizeof(expected))) {
        return -1;
    }

    uint8_t pkcs1_data_bad_prefix1[] = { 0x01, 0x02, 0x80, 0x08, 0x0c, 0x00, 0xab, 0xcd, 0xef, 0x00 };
    s2n_constant_time_pkcs1_unpad_or_dont(outbuf, pkcs1_data_bad_prefix1, sizeof(pkcs1_data_bad_prefix1), sizeof(outbuf));
    if (memcmp(outbuf, expected, sizeof(expected))) {
        return -1;
    }

    uint8_t pkcs1_data_bad_prefix2[] = { 0x00, 0x12, 0x80, 0x08, 0x0c, 0x00, 0xab, 0xcd, 0xef, 0x00 };
    s2n_constant_time_pkcs1_unpad_or_dont(outbuf, pkcs1_data_bad_prefix2, sizeof(pkcs1_data_bad_prefix2), sizeof(outbuf));
    if (memcmp(outbuf, expected, sizeof(expected))) {
        return -1;
    }

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
    EXPECT_SUCCESS(success_ct_pkcs1());
    EXPECT_SUCCESS(success_ct_pkcs1_negative());

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

    CHECK_NO_OVF(s2n_mul_overflow, uint32_t, 0, 0, 0);
    CHECK_NO_OVF(s2n_mul_overflow, uint32_t, 0, 1, 0);
    CHECK_NO_OVF(s2n_mul_overflow, uint32_t, 0, ~0u, 0);
    CHECK_NO_OVF(s2n_mul_overflow, uint32_t, 4, 5, 20);
    CHECK_NO_OVF(s2n_mul_overflow, uint32_t, 1234, 4321, 5332114);

    CHECK_NO_OVF(s2n_mul_overflow, uint32_t, 0xFFFFFFFF, 1, 0xFFFFFFFF);
    CHECK_NO_OVF(s2n_mul_overflow, uint32_t, 0xFFFF, 1, 0xFFFF);
    CHECK_NO_OVF(s2n_mul_overflow, uint32_t, 0xFFFF, 0xFFFF, 0xfffe0001u);
    CHECK_NO_OVF(s2n_mul_overflow, uint32_t, 0x10000, 0xFFFF, 0xFFFF0000u);
    CHECK_NO_OVF(s2n_mul_overflow, uint32_t, 0x10001, 0xFFFF, 0xFFFFFFFFu);
    CHECK_NO_OVF(s2n_mul_overflow, uint32_t, 0x10001, 0xFFFE, 0xFFFEFFFEu);
    CHECK_NO_OVF(s2n_mul_overflow, uint32_t, 0x10002, 0xFFFE, 0xFFFFFFFCu);
    CHECK_OVF(s2n_mul_overflow, uint32_t, 0x10003, 0xFFFE);
    CHECK_NO_OVF(s2n_mul_overflow, uint32_t, 0xFFFE, 0xFFFE, 0xFFFC0004u);
    CHECK_OVF(s2n_mul_overflow, uint32_t, 0x1FFFF, 0x1FFFF);
    CHECK_OVF(s2n_mul_overflow, uint32_t, ~0u, ~0u);

    END_TEST();
    return 0;
}
