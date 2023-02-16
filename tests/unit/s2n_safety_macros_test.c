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

/* clang-format off */

#include "s2n_test.h"

#include "utils/s2n_safety.h"

/**
 * DO NOT DIRECTLY MODIFY THIS FILE:
 *
 * The code in this file is generated from scripts/s2n_safety_macros.py and any modifications
 * should be in there.
 */

/* harnesses */

static s2n_result RESULT_BAIL_harness()
{
    RESULT_BAIL(S2N_ERR_SAFETY);
    return S2N_RESULT_OK;
}

static s2n_result RESULT_ENSURE_harness(bool is_ok)
{
    RESULT_ENSURE(is_ok, S2N_ERR_SAFETY);
    return S2N_RESULT_OK;
}

static s2n_result RESULT_DEBUG_ENSURE_harness(bool is_ok)
{
    RESULT_DEBUG_ENSURE(is_ok, S2N_ERR_SAFETY);
    return S2N_RESULT_OK;
}

static s2n_result RESULT_ENSURE_OK_harness(bool is_ok)
{
    RESULT_ENSURE_OK(RESULT_ENSURE_harness(is_ok), S2N_ERR_IO);
    return S2N_RESULT_OK;
}

static s2n_result RESULT_ENSURE_GTE_harness_uint32(uint32_t a, uint32_t b)
{
    RESULT_ENSURE_GTE(a, b);
    /* test the inverse */
    RESULT_ENSURE_LTE(b, a);
    return S2N_RESULT_OK;
}

static s2n_result RESULT_ENSURE_GTE_harness_int32(int32_t a, int32_t b)
{
    RESULT_ENSURE_GTE(a, b);
    /* test the inverse */
    RESULT_ENSURE_LTE(b, a);
    return S2N_RESULT_OK;
}

static s2n_result RESULT_ENSURE_LTE_harness_uint32(uint32_t a, uint32_t b)
{
    RESULT_ENSURE_LTE(a, b);
    /* test the inverse */
    RESULT_ENSURE_GTE(b, a);
    return S2N_RESULT_OK;
}

static s2n_result RESULT_ENSURE_LTE_harness_int32(int32_t a, int32_t b)
{
    RESULT_ENSURE_LTE(a, b);
    /* test the inverse */
    RESULT_ENSURE_GTE(b, a);
    return S2N_RESULT_OK;
}

static s2n_result RESULT_ENSURE_GT_harness_uint32(uint32_t a, uint32_t b)
{
    RESULT_ENSURE_GT(a, b);
    /* test the inverse */
    RESULT_ENSURE_LT(b, a);
    return S2N_RESULT_OK;
}

static s2n_result RESULT_ENSURE_GT_harness_int32(int32_t a, int32_t b)
{
    RESULT_ENSURE_GT(a, b);
    /* test the inverse */
    RESULT_ENSURE_LT(b, a);
    return S2N_RESULT_OK;
}

static s2n_result RESULT_ENSURE_LT_harness_uint32(uint32_t a, uint32_t b)
{
    RESULT_ENSURE_LT(a, b);
    /* test the inverse */
    RESULT_ENSURE_GT(b, a);
    return S2N_RESULT_OK;
}

static s2n_result RESULT_ENSURE_LT_harness_int32(int32_t a, int32_t b)
{
    RESULT_ENSURE_LT(a, b);
    /* test the inverse */
    RESULT_ENSURE_GT(b, a);
    return S2N_RESULT_OK;
}

static s2n_result RESULT_ENSURE_EQ_harness_uint32(uint32_t a, uint32_t b)
{
    RESULT_ENSURE_EQ(a, b);
    RESULT_ENSURE_EQ(b, a);
    return S2N_RESULT_OK;
}

static s2n_result RESULT_ENSURE_EQ_harness_int32(int32_t a, int32_t b)
{
    RESULT_ENSURE_EQ(a, b);
    RESULT_ENSURE_EQ(b, a);
    return S2N_RESULT_OK;
}

static s2n_result RESULT_ENSURE_NE_harness_uint32(uint32_t a, uint32_t b)
{
    RESULT_ENSURE_NE(a, b);
    RESULT_ENSURE_NE(b, a);
    return S2N_RESULT_OK;
}

static s2n_result RESULT_ENSURE_NE_harness_int32(int32_t a, int32_t b)
{
    RESULT_ENSURE_NE(a, b);
    RESULT_ENSURE_NE(b, a);
    return S2N_RESULT_OK;
}

static s2n_result RESULT_ENSURE_INCLUSIVE_RANGE_harness_uint32(uint32_t a, uint32_t b, uint32_t c)
{
    RESULT_ENSURE_INCLUSIVE_RANGE(a, b, c);
    return S2N_RESULT_OK;
}

static s2n_result RESULT_ENSURE_INCLUSIVE_RANGE_harness_int32(int32_t a, int32_t b, int32_t c)
{
    RESULT_ENSURE_INCLUSIVE_RANGE(a, b, c);
    return S2N_RESULT_OK;
}

static s2n_result RESULT_ENSURE_EXCLUSIVE_RANGE_harness_uint32(uint32_t a, uint32_t b, uint32_t c)
{
    RESULT_ENSURE_EXCLUSIVE_RANGE(a, b, c);
    return S2N_RESULT_OK;
}

static s2n_result RESULT_ENSURE_EXCLUSIVE_RANGE_harness_int32(int32_t a, int32_t b, int32_t c)
{
    RESULT_ENSURE_EXCLUSIVE_RANGE(a, b, c);
    return S2N_RESULT_OK;
}

static s2n_result RESULT_ENSURE_REF_harness(const char* str)
{
    RESULT_ENSURE_REF(str);
    return S2N_RESULT_OK;
}

static s2n_result RESULT_ENSURE_MUT_harness(uint32_t* v)
{
    RESULT_ENSURE_MUT(v);
    return S2N_RESULT_OK;
}

static S2N_RESULT RESULT_PRECONDITION_harness_check(bool is_ok)
{
    RESULT_ENSURE(is_ok, S2N_ERR_SAFETY);
    return S2N_RESULT_OK;
}

static s2n_result RESULT_PRECONDITION_harness(s2n_result result)
{
    RESULT_PRECONDITION(result);
    return S2N_RESULT_OK;
}

static S2N_RESULT RESULT_POSTCONDITION_harness_check(bool is_ok)
{
    RESULT_ENSURE(is_ok, S2N_ERR_SAFETY);
    return S2N_RESULT_OK;
}

static s2n_result RESULT_POSTCONDITION_harness(s2n_result result)
{
    RESULT_POSTCONDITION(result);
    return S2N_RESULT_OK;
}

static s2n_result RESULT_CHECKED_MEMCPY_harness(uint32_t* dest, uint32_t* source, size_t len)
{
    RESULT_CHECKED_MEMCPY(dest, source, len);
    return S2N_RESULT_OK;
}

static s2n_result RESULT_CHECKED_MEMSET_harness(uint32_t* dest, uint8_t value, size_t len)
{
    RESULT_CHECKED_MEMSET(dest, value, len);
    return S2N_RESULT_OK;
}

static s2n_result RESULT_GUARD_harness(s2n_result result)
{
    RESULT_GUARD(result);
    return S2N_RESULT_OK;
}

static s2n_result RESULT_GUARD_OSSL_harness(int result, int error)
{
    RESULT_GUARD_OSSL(result, error);
    return S2N_RESULT_OK;
}

static int POSIX_BAIL_harness()
{
    POSIX_BAIL(S2N_ERR_SAFETY);
    return S2N_SUCCESS;
}

static int POSIX_ENSURE_harness(bool is_ok)
{
    POSIX_ENSURE(is_ok, S2N_ERR_SAFETY);
    return S2N_SUCCESS;
}

static int POSIX_DEBUG_ENSURE_harness(bool is_ok)
{
    POSIX_DEBUG_ENSURE(is_ok, S2N_ERR_SAFETY);
    return S2N_SUCCESS;
}

static int POSIX_ENSURE_OK_harness(bool is_ok)
{
    POSIX_ENSURE_OK(POSIX_ENSURE_harness(is_ok), S2N_ERR_IO);
    return S2N_SUCCESS;
}

static int POSIX_ENSURE_GTE_harness_uint32(uint32_t a, uint32_t b)
{
    POSIX_ENSURE_GTE(a, b);
    /* test the inverse */
    POSIX_ENSURE_LTE(b, a);
    return S2N_SUCCESS;
}

static int POSIX_ENSURE_GTE_harness_int32(int32_t a, int32_t b)
{
    POSIX_ENSURE_GTE(a, b);
    /* test the inverse */
    POSIX_ENSURE_LTE(b, a);
    return S2N_SUCCESS;
}

static int POSIX_ENSURE_LTE_harness_uint32(uint32_t a, uint32_t b)
{
    POSIX_ENSURE_LTE(a, b);
    /* test the inverse */
    POSIX_ENSURE_GTE(b, a);
    return S2N_SUCCESS;
}

static int POSIX_ENSURE_LTE_harness_int32(int32_t a, int32_t b)
{
    POSIX_ENSURE_LTE(a, b);
    /* test the inverse */
    POSIX_ENSURE_GTE(b, a);
    return S2N_SUCCESS;
}

static int POSIX_ENSURE_GT_harness_uint32(uint32_t a, uint32_t b)
{
    POSIX_ENSURE_GT(a, b);
    /* test the inverse */
    POSIX_ENSURE_LT(b, a);
    return S2N_SUCCESS;
}

static int POSIX_ENSURE_GT_harness_int32(int32_t a, int32_t b)
{
    POSIX_ENSURE_GT(a, b);
    /* test the inverse */
    POSIX_ENSURE_LT(b, a);
    return S2N_SUCCESS;
}

static int POSIX_ENSURE_LT_harness_uint32(uint32_t a, uint32_t b)
{
    POSIX_ENSURE_LT(a, b);
    /* test the inverse */
    POSIX_ENSURE_GT(b, a);
    return S2N_SUCCESS;
}

static int POSIX_ENSURE_LT_harness_int32(int32_t a, int32_t b)
{
    POSIX_ENSURE_LT(a, b);
    /* test the inverse */
    POSIX_ENSURE_GT(b, a);
    return S2N_SUCCESS;
}

static int POSIX_ENSURE_EQ_harness_uint32(uint32_t a, uint32_t b)
{
    POSIX_ENSURE_EQ(a, b);
    POSIX_ENSURE_EQ(b, a);
    return S2N_SUCCESS;
}

static int POSIX_ENSURE_EQ_harness_int32(int32_t a, int32_t b)
{
    POSIX_ENSURE_EQ(a, b);
    POSIX_ENSURE_EQ(b, a);
    return S2N_SUCCESS;
}

static int POSIX_ENSURE_NE_harness_uint32(uint32_t a, uint32_t b)
{
    POSIX_ENSURE_NE(a, b);
    POSIX_ENSURE_NE(b, a);
    return S2N_SUCCESS;
}

static int POSIX_ENSURE_NE_harness_int32(int32_t a, int32_t b)
{
    POSIX_ENSURE_NE(a, b);
    POSIX_ENSURE_NE(b, a);
    return S2N_SUCCESS;
}

static int POSIX_ENSURE_INCLUSIVE_RANGE_harness_uint32(uint32_t a, uint32_t b, uint32_t c)
{
    POSIX_ENSURE_INCLUSIVE_RANGE(a, b, c);
    return S2N_SUCCESS;
}

static int POSIX_ENSURE_INCLUSIVE_RANGE_harness_int32(int32_t a, int32_t b, int32_t c)
{
    POSIX_ENSURE_INCLUSIVE_RANGE(a, b, c);
    return S2N_SUCCESS;
}

static int POSIX_ENSURE_EXCLUSIVE_RANGE_harness_uint32(uint32_t a, uint32_t b, uint32_t c)
{
    POSIX_ENSURE_EXCLUSIVE_RANGE(a, b, c);
    return S2N_SUCCESS;
}

static int POSIX_ENSURE_EXCLUSIVE_RANGE_harness_int32(int32_t a, int32_t b, int32_t c)
{
    POSIX_ENSURE_EXCLUSIVE_RANGE(a, b, c);
    return S2N_SUCCESS;
}

static int POSIX_ENSURE_REF_harness(const char* str)
{
    POSIX_ENSURE_REF(str);
    return S2N_SUCCESS;
}

static int POSIX_ENSURE_MUT_harness(uint32_t* v)
{
    POSIX_ENSURE_MUT(v);
    return S2N_SUCCESS;
}

static S2N_RESULT POSIX_PRECONDITION_harness_check(bool is_ok)
{
    RESULT_ENSURE(is_ok, S2N_ERR_SAFETY);
    return S2N_RESULT_OK;
}

static int POSIX_PRECONDITION_harness(s2n_result result)
{
    POSIX_PRECONDITION(result);
    return S2N_SUCCESS;
}

static S2N_RESULT POSIX_POSTCONDITION_harness_check(bool is_ok)
{
    RESULT_ENSURE(is_ok, S2N_ERR_SAFETY);
    return S2N_RESULT_OK;
}

static int POSIX_POSTCONDITION_harness(s2n_result result)
{
    POSIX_POSTCONDITION(result);
    return S2N_SUCCESS;
}

static int POSIX_CHECKED_MEMCPY_harness(uint32_t* dest, uint32_t* source, size_t len)
{
    POSIX_CHECKED_MEMCPY(dest, source, len);
    return S2N_SUCCESS;
}

static int POSIX_CHECKED_MEMSET_harness(uint32_t* dest, uint8_t value, size_t len)
{
    POSIX_CHECKED_MEMSET(dest, value, len);
    return S2N_SUCCESS;
}

static int POSIX_GUARD_harness(int result)
{
    POSIX_GUARD(result);
    return S2N_SUCCESS;
}

static int POSIX_GUARD_OSSL_harness(int result, int error)
{
    POSIX_GUARD_OSSL(result, error);
    return S2N_SUCCESS;
}

static const char* PTR_BAIL_harness()
{
    PTR_BAIL(S2N_ERR_SAFETY);
    return "ok";
}

static const char* PTR_ENSURE_harness(bool is_ok)
{
    PTR_ENSURE(is_ok, S2N_ERR_SAFETY);
    return "ok";
}

static const char* PTR_DEBUG_ENSURE_harness(bool is_ok)
{
    PTR_DEBUG_ENSURE(is_ok, S2N_ERR_SAFETY);
    return "ok";
}

static const char* PTR_ENSURE_OK_harness(bool is_ok)
{
    PTR_ENSURE_OK(PTR_ENSURE_harness(is_ok), S2N_ERR_IO);
    return "ok";
}

static const char* PTR_ENSURE_GTE_harness_uint32(uint32_t a, uint32_t b)
{
    PTR_ENSURE_GTE(a, b);
    /* test the inverse */
    PTR_ENSURE_LTE(b, a);
    return "ok";
}

static const char* PTR_ENSURE_GTE_harness_int32(int32_t a, int32_t b)
{
    PTR_ENSURE_GTE(a, b);
    /* test the inverse */
    PTR_ENSURE_LTE(b, a);
    return "ok";
}

static const char* PTR_ENSURE_LTE_harness_uint32(uint32_t a, uint32_t b)
{
    PTR_ENSURE_LTE(a, b);
    /* test the inverse */
    PTR_ENSURE_GTE(b, a);
    return "ok";
}

static const char* PTR_ENSURE_LTE_harness_int32(int32_t a, int32_t b)
{
    PTR_ENSURE_LTE(a, b);
    /* test the inverse */
    PTR_ENSURE_GTE(b, a);
    return "ok";
}

static const char* PTR_ENSURE_GT_harness_uint32(uint32_t a, uint32_t b)
{
    PTR_ENSURE_GT(a, b);
    /* test the inverse */
    PTR_ENSURE_LT(b, a);
    return "ok";
}

static const char* PTR_ENSURE_GT_harness_int32(int32_t a, int32_t b)
{
    PTR_ENSURE_GT(a, b);
    /* test the inverse */
    PTR_ENSURE_LT(b, a);
    return "ok";
}

static const char* PTR_ENSURE_LT_harness_uint32(uint32_t a, uint32_t b)
{
    PTR_ENSURE_LT(a, b);
    /* test the inverse */
    PTR_ENSURE_GT(b, a);
    return "ok";
}

static const char* PTR_ENSURE_LT_harness_int32(int32_t a, int32_t b)
{
    PTR_ENSURE_LT(a, b);
    /* test the inverse */
    PTR_ENSURE_GT(b, a);
    return "ok";
}

static const char* PTR_ENSURE_EQ_harness_uint32(uint32_t a, uint32_t b)
{
    PTR_ENSURE_EQ(a, b);
    PTR_ENSURE_EQ(b, a);
    return "ok";
}

static const char* PTR_ENSURE_EQ_harness_int32(int32_t a, int32_t b)
{
    PTR_ENSURE_EQ(a, b);
    PTR_ENSURE_EQ(b, a);
    return "ok";
}

static const char* PTR_ENSURE_NE_harness_uint32(uint32_t a, uint32_t b)
{
    PTR_ENSURE_NE(a, b);
    PTR_ENSURE_NE(b, a);
    return "ok";
}

static const char* PTR_ENSURE_NE_harness_int32(int32_t a, int32_t b)
{
    PTR_ENSURE_NE(a, b);
    PTR_ENSURE_NE(b, a);
    return "ok";
}

static const char* PTR_ENSURE_INCLUSIVE_RANGE_harness_uint32(uint32_t a, uint32_t b, uint32_t c)
{
    PTR_ENSURE_INCLUSIVE_RANGE(a, b, c);
    return "ok";
}

static const char* PTR_ENSURE_INCLUSIVE_RANGE_harness_int32(int32_t a, int32_t b, int32_t c)
{
    PTR_ENSURE_INCLUSIVE_RANGE(a, b, c);
    return "ok";
}

static const char* PTR_ENSURE_EXCLUSIVE_RANGE_harness_uint32(uint32_t a, uint32_t b, uint32_t c)
{
    PTR_ENSURE_EXCLUSIVE_RANGE(a, b, c);
    return "ok";
}

static const char* PTR_ENSURE_EXCLUSIVE_RANGE_harness_int32(int32_t a, int32_t b, int32_t c)
{
    PTR_ENSURE_EXCLUSIVE_RANGE(a, b, c);
    return "ok";
}

static const char* PTR_ENSURE_REF_harness(const char* str)
{
    PTR_ENSURE_REF(str);
    return "ok";
}

static const char* PTR_ENSURE_MUT_harness(uint32_t* v)
{
    PTR_ENSURE_MUT(v);
    return "ok";
}

static S2N_RESULT PTR_PRECONDITION_harness_check(bool is_ok)
{
    RESULT_ENSURE(is_ok, S2N_ERR_SAFETY);
    return S2N_RESULT_OK;
}

static const char* PTR_PRECONDITION_harness(s2n_result result)
{
    PTR_PRECONDITION(result);
    return "ok";
}

static S2N_RESULT PTR_POSTCONDITION_harness_check(bool is_ok)
{
    RESULT_ENSURE(is_ok, S2N_ERR_SAFETY);
    return S2N_RESULT_OK;
}

static const char* PTR_POSTCONDITION_harness(s2n_result result)
{
    PTR_POSTCONDITION(result);
    return "ok";
}

static const char* PTR_CHECKED_MEMCPY_harness(uint32_t* dest, uint32_t* source, size_t len)
{
    PTR_CHECKED_MEMCPY(dest, source, len);
    return "ok";
}

static const char* PTR_CHECKED_MEMSET_harness(uint32_t* dest, uint8_t value, size_t len)
{
    PTR_CHECKED_MEMSET(dest, value, len);
    return "ok";
}

static const char* PTR_GUARD_harness(const char* result)
{
    PTR_GUARD(result);
    return "ok";
}

static const char* PTR_GUARD_OSSL_harness(int result, int error)
{
    PTR_GUARD_OSSL(result, error);
    return "ok";
}

int main(int argc, char **argv)
{
    BEGIN_TEST();

    /* RESULT_BAIL(error) */
    EXPECT_ERROR_WITH_ERRNO(RESULT_BAIL_harness(), S2N_ERR_SAFETY);

    /* RESULT_ENSURE(condition, error) */
    EXPECT_OK(RESULT_ENSURE_harness(true));
    EXPECT_ERROR_WITH_ERRNO(RESULT_ENSURE_harness(false), S2N_ERR_SAFETY);

    /* RESULT_DEBUG_ENSURE(condition, error) */
    EXPECT_OK(RESULT_DEBUG_ENSURE_harness(true));
    #ifdef NDEBUG
    EXPECT_OK(RESULT_DEBUG_ENSURE_harness(false));
    #else
    EXPECT_ERROR_WITH_ERRNO(RESULT_DEBUG_ENSURE_harness(false), S2N_ERR_SAFETY);
    #endif

    /* RESULT_ENSURE_OK(result, error) */
    EXPECT_OK(RESULT_ENSURE_OK_harness(true));
    EXPECT_ERROR_WITH_ERRNO(RESULT_ENSURE_OK_harness(false), S2N_ERR_IO);

    /* RESULT_ENSURE_GTE(a, b) */
    EXPECT_OK(RESULT_ENSURE_GTE_harness_uint32(0, 0));
    EXPECT_OK(RESULT_ENSURE_GTE_harness_uint32(1, 0));
    EXPECT_ERROR_WITH_ERRNO(RESULT_ENSURE_GTE_harness_uint32(0, 1), S2N_ERR_SAFETY);
    EXPECT_OK(RESULT_ENSURE_GTE_harness_int32(-1, -2));
    EXPECT_OK(RESULT_ENSURE_GTE_harness_int32(-1, -1));
    EXPECT_ERROR_WITH_ERRNO(RESULT_ENSURE_GTE_harness_int32(-2, -1), S2N_ERR_SAFETY);

    /* RESULT_ENSURE_LTE(a, b) */
    EXPECT_OK(RESULT_ENSURE_LTE_harness_uint32(0, 0));
    EXPECT_OK(RESULT_ENSURE_LTE_harness_uint32(0, 1));
    EXPECT_ERROR_WITH_ERRNO(RESULT_ENSURE_LTE_harness_uint32(1, 0), S2N_ERR_SAFETY);
    EXPECT_OK(RESULT_ENSURE_LTE_harness_int32(-2, -1));
    EXPECT_OK(RESULT_ENSURE_LTE_harness_int32(-1, -1));
    EXPECT_ERROR_WITH_ERRNO(RESULT_ENSURE_LTE_harness_int32(-1, -2), S2N_ERR_SAFETY);

    /* RESULT_ENSURE_GT(a, b) */
    EXPECT_ERROR_WITH_ERRNO(RESULT_ENSURE_GT_harness_uint32(0, 0), S2N_ERR_SAFETY);
    EXPECT_OK(RESULT_ENSURE_GT_harness_uint32(1, 0));
    EXPECT_ERROR_WITH_ERRNO(RESULT_ENSURE_GT_harness_uint32(0, 1), S2N_ERR_SAFETY);
    EXPECT_OK(RESULT_ENSURE_GT_harness_int32(-1, -2));
    EXPECT_ERROR_WITH_ERRNO(RESULT_ENSURE_GT_harness_int32(-1, -1), S2N_ERR_SAFETY);
    EXPECT_ERROR_WITH_ERRNO(RESULT_ENSURE_GT_harness_int32(-2, -1), S2N_ERR_SAFETY);

    /* RESULT_ENSURE_LT(a, b) */
    EXPECT_ERROR_WITH_ERRNO(RESULT_ENSURE_LT_harness_uint32(0, 0), S2N_ERR_SAFETY);
    EXPECT_OK(RESULT_ENSURE_LT_harness_uint32(0, 1));
    EXPECT_ERROR_WITH_ERRNO(RESULT_ENSURE_LT_harness_uint32(1, 0), S2N_ERR_SAFETY);
    EXPECT_OK(RESULT_ENSURE_LT_harness_int32(-2, -1));
    EXPECT_ERROR_WITH_ERRNO(RESULT_ENSURE_LT_harness_int32(-1, -1), S2N_ERR_SAFETY);
    EXPECT_ERROR_WITH_ERRNO(RESULT_ENSURE_LT_harness_int32(-1, -2), S2N_ERR_SAFETY);

    /* RESULT_ENSURE_EQ(a, b) */
    EXPECT_OK(RESULT_ENSURE_EQ_harness_uint32(0, 0));
    EXPECT_ERROR_WITH_ERRNO(RESULT_ENSURE_EQ_harness_uint32(1, 0), S2N_ERR_SAFETY);
    EXPECT_OK(RESULT_ENSURE_EQ_harness_int32(-1, -1));
    EXPECT_ERROR_WITH_ERRNO(RESULT_ENSURE_EQ_harness_int32(-2, -1), S2N_ERR_SAFETY);

    /* RESULT_ENSURE_NE(a, b) */
    EXPECT_OK(RESULT_ENSURE_NE_harness_uint32(1, 0));
    EXPECT_ERROR_WITH_ERRNO(RESULT_ENSURE_NE_harness_uint32(0, 0), S2N_ERR_SAFETY);
    EXPECT_OK(RESULT_ENSURE_NE_harness_int32(-2, -1));
    EXPECT_ERROR_WITH_ERRNO(RESULT_ENSURE_NE_harness_int32(-1, -1), S2N_ERR_SAFETY);

    /* RESULT_ENSURE_INCLUSIVE_RANGE(min, n, max) */
    EXPECT_ERROR_WITH_ERRNO(RESULT_ENSURE_INCLUSIVE_RANGE_harness_uint32(1, 0, 2), S2N_ERR_SAFETY);
    EXPECT_OK(RESULT_ENSURE_INCLUSIVE_RANGE_harness_uint32(1, 1, 2));
    EXPECT_OK(RESULT_ENSURE_INCLUSIVE_RANGE_harness_uint32(1, 2, 2));
    EXPECT_ERROR_WITH_ERRNO(RESULT_ENSURE_INCLUSIVE_RANGE_harness_uint32(1, 3, 2), S2N_ERR_SAFETY);
    EXPECT_ERROR_WITH_ERRNO(RESULT_ENSURE_INCLUSIVE_RANGE_harness_int32(-2, -3, -1), S2N_ERR_SAFETY);
    EXPECT_OK(RESULT_ENSURE_INCLUSIVE_RANGE_harness_int32(-2, -2, -1));
    EXPECT_OK(RESULT_ENSURE_INCLUSIVE_RANGE_harness_int32(-2, -1, -1));
    EXPECT_ERROR_WITH_ERRNO(RESULT_ENSURE_INCLUSIVE_RANGE_harness_int32(-2, 0, -1), S2N_ERR_SAFETY);

    /* RESULT_ENSURE_EXCLUSIVE_RANGE(min, n, max) */
    EXPECT_ERROR_WITH_ERRNO(RESULT_ENSURE_EXCLUSIVE_RANGE_harness_uint32(1, 0, 3), S2N_ERR_SAFETY);
    EXPECT_ERROR_WITH_ERRNO(RESULT_ENSURE_EXCLUSIVE_RANGE_harness_uint32(1, 1, 3), S2N_ERR_SAFETY);
    EXPECT_OK(RESULT_ENSURE_EXCLUSIVE_RANGE_harness_uint32(1, 2, 3));
    EXPECT_ERROR_WITH_ERRNO(RESULT_ENSURE_EXCLUSIVE_RANGE_harness_uint32(1, 3, 3), S2N_ERR_SAFETY);
    EXPECT_ERROR_WITH_ERRNO(RESULT_ENSURE_EXCLUSIVE_RANGE_harness_uint32(1, 4, 3), S2N_ERR_SAFETY);
    EXPECT_ERROR_WITH_ERRNO(RESULT_ENSURE_EXCLUSIVE_RANGE_harness_int32(-3, -4, -1), S2N_ERR_SAFETY);
    EXPECT_ERROR_WITH_ERRNO(RESULT_ENSURE_EXCLUSIVE_RANGE_harness_int32(-3, -3, -1), S2N_ERR_SAFETY);
    EXPECT_OK(RESULT_ENSURE_EXCLUSIVE_RANGE_harness_int32(-3, -2, -1));
    EXPECT_ERROR_WITH_ERRNO(RESULT_ENSURE_EXCLUSIVE_RANGE_harness_int32(-3, -1, -1), S2N_ERR_SAFETY);
    EXPECT_ERROR_WITH_ERRNO(RESULT_ENSURE_EXCLUSIVE_RANGE_harness_int32(-3, 0, -1), S2N_ERR_SAFETY);

    /* RESULT_ENSURE_REF(x) */
    EXPECT_OK(RESULT_ENSURE_REF_harness(""));
    EXPECT_OK(RESULT_ENSURE_REF_harness("ok"));
    EXPECT_ERROR_WITH_ERRNO(RESULT_ENSURE_REF_harness(NULL), S2N_ERR_NULL);

    /* RESULT_ENSURE_MUT(x) */
    uint32_t RESULT_ensure_mut_test = 0;
    EXPECT_OK(RESULT_ENSURE_MUT_harness(&RESULT_ensure_mut_test));
    RESULT_ensure_mut_test = 1;
    EXPECT_OK(RESULT_ENSURE_MUT_harness(&RESULT_ensure_mut_test));
    EXPECT_ERROR_WITH_ERRNO(RESULT_ENSURE_MUT_harness(NULL), S2N_ERR_NULL);

    /* RESULT_PRECONDITION(result) */
    EXPECT_OK(RESULT_PRECONDITION_harness(RESULT_PRECONDITION_harness_check(true)));
    EXPECT_ERROR_WITH_ERRNO(RESULT_PRECONDITION_harness(RESULT_PRECONDITION_harness_check(false)), S2N_ERR_SAFETY);

    /* RESULT_POSTCONDITION(result) */
    EXPECT_OK(RESULT_POSTCONDITION_harness(RESULT_POSTCONDITION_harness_check(true)));
    #ifdef NDEBUG
    EXPECT_OK(RESULT_POSTCONDITION_harness(RESULT_POSTCONDITION_harness_check(false)));
    #else
    EXPECT_ERROR_WITH_ERRNO(RESULT_POSTCONDITION_harness(RESULT_POSTCONDITION_harness_check(false)), S2N_ERR_SAFETY);
    #endif

    /* RESULT_CHECKED_MEMCPY(destination, source, len) */
    uint32_t RESULT__checked_memcpy_dest = 1;
    uint32_t RESULT__checked_memcpy_source = 2;
    EXPECT_OK(RESULT_CHECKED_MEMCPY_harness(&RESULT__checked_memcpy_dest, &RESULT__checked_memcpy_source, 0));
    EXPECT_EQUAL(RESULT__checked_memcpy_dest, 1);
    EXPECT_ERROR_WITH_ERRNO(RESULT_CHECKED_MEMCPY_harness(NULL, &RESULT__checked_memcpy_source, 4), S2N_ERR_NULL);
    EXPECT_ERROR_WITH_ERRNO(RESULT_CHECKED_MEMCPY_harness(&RESULT__checked_memcpy_dest, NULL, 4), S2N_ERR_NULL);
    EXPECT_OK(RESULT_CHECKED_MEMCPY_harness(&RESULT__checked_memcpy_dest, &RESULT__checked_memcpy_source, 4));
    EXPECT_EQUAL(RESULT__checked_memcpy_dest, RESULT__checked_memcpy_source);

    /* RESULT_CHECKED_MEMSET(destination, value, len) */
    uint32_t RESULT__checked_memset_dest = 1;
    EXPECT_OK(RESULT_CHECKED_MEMSET_harness(&RESULT__checked_memset_dest, 0x42, 0));
    EXPECT_EQUAL(RESULT__checked_memset_dest, 1);
    EXPECT_ERROR_WITH_ERRNO(RESULT_CHECKED_MEMSET_harness(NULL, 0x42, 1), S2N_ERR_NULL);
    EXPECT_OK(RESULT_CHECKED_MEMSET_harness(&RESULT__checked_memset_dest, 0x42, 4));
    EXPECT_EQUAL(RESULT__checked_memset_dest, 0x42424242);

    /* RESULT_GUARD(result) */
    EXPECT_OK(RESULT_GUARD_harness(RESULT_ENSURE_harness(true)));
    EXPECT_ERROR_WITH_ERRNO(RESULT_GUARD_harness(RESULT_ENSURE_harness(false)), S2N_ERR_SAFETY);

    /* RESULT_GUARD_OSSL(result, error) */
    EXPECT_OK(RESULT_GUARD_OSSL_harness(1, S2N_ERR_SAFETY));
    EXPECT_ERROR_WITH_ERRNO(RESULT_GUARD_OSSL_harness(0, S2N_ERR_SAFETY), S2N_ERR_SAFETY);

    /* POSIX_BAIL(error) */
    EXPECT_FAILURE_WITH_ERRNO(POSIX_BAIL_harness(), S2N_ERR_SAFETY);

    /* POSIX_ENSURE(condition, error) */
    EXPECT_SUCCESS(POSIX_ENSURE_harness(true));
    EXPECT_FAILURE_WITH_ERRNO(POSIX_ENSURE_harness(false), S2N_ERR_SAFETY);

    /* POSIX_DEBUG_ENSURE(condition, error) */
    EXPECT_SUCCESS(POSIX_DEBUG_ENSURE_harness(true));
    #ifdef NDEBUG
    EXPECT_SUCCESS(POSIX_DEBUG_ENSURE_harness(false));
    #else
    EXPECT_FAILURE_WITH_ERRNO(POSIX_DEBUG_ENSURE_harness(false), S2N_ERR_SAFETY);
    #endif

    /* POSIX_ENSURE_OK(result, error) */
    EXPECT_SUCCESS(POSIX_ENSURE_OK_harness(true));
    EXPECT_FAILURE_WITH_ERRNO(POSIX_ENSURE_OK_harness(false), S2N_ERR_IO);

    /* POSIX_ENSURE_GTE(a, b) */
    EXPECT_SUCCESS(POSIX_ENSURE_GTE_harness_uint32(0, 0));
    EXPECT_SUCCESS(POSIX_ENSURE_GTE_harness_uint32(1, 0));
    EXPECT_FAILURE_WITH_ERRNO(POSIX_ENSURE_GTE_harness_uint32(0, 1), S2N_ERR_SAFETY);
    EXPECT_SUCCESS(POSIX_ENSURE_GTE_harness_int32(-1, -2));
    EXPECT_SUCCESS(POSIX_ENSURE_GTE_harness_int32(-1, -1));
    EXPECT_FAILURE_WITH_ERRNO(POSIX_ENSURE_GTE_harness_int32(-2, -1), S2N_ERR_SAFETY);

    /* POSIX_ENSURE_LTE(a, b) */
    EXPECT_SUCCESS(POSIX_ENSURE_LTE_harness_uint32(0, 0));
    EXPECT_SUCCESS(POSIX_ENSURE_LTE_harness_uint32(0, 1));
    EXPECT_FAILURE_WITH_ERRNO(POSIX_ENSURE_LTE_harness_uint32(1, 0), S2N_ERR_SAFETY);
    EXPECT_SUCCESS(POSIX_ENSURE_LTE_harness_int32(-2, -1));
    EXPECT_SUCCESS(POSIX_ENSURE_LTE_harness_int32(-1, -1));
    EXPECT_FAILURE_WITH_ERRNO(POSIX_ENSURE_LTE_harness_int32(-1, -2), S2N_ERR_SAFETY);

    /* POSIX_ENSURE_GT(a, b) */
    EXPECT_FAILURE_WITH_ERRNO(POSIX_ENSURE_GT_harness_uint32(0, 0), S2N_ERR_SAFETY);
    EXPECT_SUCCESS(POSIX_ENSURE_GT_harness_uint32(1, 0));
    EXPECT_FAILURE_WITH_ERRNO(POSIX_ENSURE_GT_harness_uint32(0, 1), S2N_ERR_SAFETY);
    EXPECT_SUCCESS(POSIX_ENSURE_GT_harness_int32(-1, -2));
    EXPECT_FAILURE_WITH_ERRNO(POSIX_ENSURE_GT_harness_int32(-1, -1), S2N_ERR_SAFETY);
    EXPECT_FAILURE_WITH_ERRNO(POSIX_ENSURE_GT_harness_int32(-2, -1), S2N_ERR_SAFETY);

    /* POSIX_ENSURE_LT(a, b) */
    EXPECT_FAILURE_WITH_ERRNO(POSIX_ENSURE_LT_harness_uint32(0, 0), S2N_ERR_SAFETY);
    EXPECT_SUCCESS(POSIX_ENSURE_LT_harness_uint32(0, 1));
    EXPECT_FAILURE_WITH_ERRNO(POSIX_ENSURE_LT_harness_uint32(1, 0), S2N_ERR_SAFETY);
    EXPECT_SUCCESS(POSIX_ENSURE_LT_harness_int32(-2, -1));
    EXPECT_FAILURE_WITH_ERRNO(POSIX_ENSURE_LT_harness_int32(-1, -1), S2N_ERR_SAFETY);
    EXPECT_FAILURE_WITH_ERRNO(POSIX_ENSURE_LT_harness_int32(-1, -2), S2N_ERR_SAFETY);

    /* POSIX_ENSURE_EQ(a, b) */
    EXPECT_SUCCESS(POSIX_ENSURE_EQ_harness_uint32(0, 0));
    EXPECT_FAILURE_WITH_ERRNO(POSIX_ENSURE_EQ_harness_uint32(1, 0), S2N_ERR_SAFETY);
    EXPECT_SUCCESS(POSIX_ENSURE_EQ_harness_int32(-1, -1));
    EXPECT_FAILURE_WITH_ERRNO(POSIX_ENSURE_EQ_harness_int32(-2, -1), S2N_ERR_SAFETY);

    /* POSIX_ENSURE_NE(a, b) */
    EXPECT_SUCCESS(POSIX_ENSURE_NE_harness_uint32(1, 0));
    EXPECT_FAILURE_WITH_ERRNO(POSIX_ENSURE_NE_harness_uint32(0, 0), S2N_ERR_SAFETY);
    EXPECT_SUCCESS(POSIX_ENSURE_NE_harness_int32(-2, -1));
    EXPECT_FAILURE_WITH_ERRNO(POSIX_ENSURE_NE_harness_int32(-1, -1), S2N_ERR_SAFETY);

    /* POSIX_ENSURE_INCLUSIVE_RANGE(min, n, max) */
    EXPECT_FAILURE_WITH_ERRNO(POSIX_ENSURE_INCLUSIVE_RANGE_harness_uint32(1, 0, 2), S2N_ERR_SAFETY);
    EXPECT_SUCCESS(POSIX_ENSURE_INCLUSIVE_RANGE_harness_uint32(1, 1, 2));
    EXPECT_SUCCESS(POSIX_ENSURE_INCLUSIVE_RANGE_harness_uint32(1, 2, 2));
    EXPECT_FAILURE_WITH_ERRNO(POSIX_ENSURE_INCLUSIVE_RANGE_harness_uint32(1, 3, 2), S2N_ERR_SAFETY);
    EXPECT_FAILURE_WITH_ERRNO(POSIX_ENSURE_INCLUSIVE_RANGE_harness_int32(-2, -3, -1), S2N_ERR_SAFETY);
    EXPECT_SUCCESS(POSIX_ENSURE_INCLUSIVE_RANGE_harness_int32(-2, -2, -1));
    EXPECT_SUCCESS(POSIX_ENSURE_INCLUSIVE_RANGE_harness_int32(-2, -1, -1));
    EXPECT_FAILURE_WITH_ERRNO(POSIX_ENSURE_INCLUSIVE_RANGE_harness_int32(-2, 0, -1), S2N_ERR_SAFETY);

    /* POSIX_ENSURE_EXCLUSIVE_RANGE(min, n, max) */
    EXPECT_FAILURE_WITH_ERRNO(POSIX_ENSURE_EXCLUSIVE_RANGE_harness_uint32(1, 0, 3), S2N_ERR_SAFETY);
    EXPECT_FAILURE_WITH_ERRNO(POSIX_ENSURE_EXCLUSIVE_RANGE_harness_uint32(1, 1, 3), S2N_ERR_SAFETY);
    EXPECT_SUCCESS(POSIX_ENSURE_EXCLUSIVE_RANGE_harness_uint32(1, 2, 3));
    EXPECT_FAILURE_WITH_ERRNO(POSIX_ENSURE_EXCLUSIVE_RANGE_harness_uint32(1, 3, 3), S2N_ERR_SAFETY);
    EXPECT_FAILURE_WITH_ERRNO(POSIX_ENSURE_EXCLUSIVE_RANGE_harness_uint32(1, 4, 3), S2N_ERR_SAFETY);
    EXPECT_FAILURE_WITH_ERRNO(POSIX_ENSURE_EXCLUSIVE_RANGE_harness_int32(-3, -4, -1), S2N_ERR_SAFETY);
    EXPECT_FAILURE_WITH_ERRNO(POSIX_ENSURE_EXCLUSIVE_RANGE_harness_int32(-3, -3, -1), S2N_ERR_SAFETY);
    EXPECT_SUCCESS(POSIX_ENSURE_EXCLUSIVE_RANGE_harness_int32(-3, -2, -1));
    EXPECT_FAILURE_WITH_ERRNO(POSIX_ENSURE_EXCLUSIVE_RANGE_harness_int32(-3, -1, -1), S2N_ERR_SAFETY);
    EXPECT_FAILURE_WITH_ERRNO(POSIX_ENSURE_EXCLUSIVE_RANGE_harness_int32(-3, 0, -1), S2N_ERR_SAFETY);

    /* POSIX_ENSURE_REF(x) */
    EXPECT_SUCCESS(POSIX_ENSURE_REF_harness(""));
    EXPECT_SUCCESS(POSIX_ENSURE_REF_harness("ok"));
    EXPECT_FAILURE_WITH_ERRNO(POSIX_ENSURE_REF_harness(NULL), S2N_ERR_NULL);

    /* POSIX_ENSURE_MUT(x) */
    uint32_t POSIX_ensure_mut_test = 0;
    EXPECT_SUCCESS(POSIX_ENSURE_MUT_harness(&POSIX_ensure_mut_test));
    POSIX_ensure_mut_test = 1;
    EXPECT_SUCCESS(POSIX_ENSURE_MUT_harness(&POSIX_ensure_mut_test));
    EXPECT_FAILURE_WITH_ERRNO(POSIX_ENSURE_MUT_harness(NULL), S2N_ERR_NULL);

    /* POSIX_PRECONDITION(result) */
    EXPECT_SUCCESS(POSIX_PRECONDITION_harness(POSIX_PRECONDITION_harness_check(true)));
    EXPECT_FAILURE_WITH_ERRNO(POSIX_PRECONDITION_harness(POSIX_PRECONDITION_harness_check(false)), S2N_ERR_SAFETY);

    /* POSIX_POSTCONDITION(result) */
    EXPECT_SUCCESS(POSIX_POSTCONDITION_harness(POSIX_POSTCONDITION_harness_check(true)));
    #ifdef NDEBUG
    EXPECT_SUCCESS(POSIX_POSTCONDITION_harness(POSIX_POSTCONDITION_harness_check(false)));
    #else
    EXPECT_FAILURE_WITH_ERRNO(POSIX_POSTCONDITION_harness(POSIX_POSTCONDITION_harness_check(false)), S2N_ERR_SAFETY);
    #endif

    /* POSIX_CHECKED_MEMCPY(destination, source, len) */
    uint32_t POSIX__checked_memcpy_dest = 1;
    uint32_t POSIX__checked_memcpy_source = 2;
    EXPECT_SUCCESS(POSIX_CHECKED_MEMCPY_harness(&POSIX__checked_memcpy_dest, &POSIX__checked_memcpy_source, 0));
    EXPECT_EQUAL(POSIX__checked_memcpy_dest, 1);
    EXPECT_FAILURE_WITH_ERRNO(POSIX_CHECKED_MEMCPY_harness(NULL, &POSIX__checked_memcpy_source, 4), S2N_ERR_NULL);
    EXPECT_FAILURE_WITH_ERRNO(POSIX_CHECKED_MEMCPY_harness(&POSIX__checked_memcpy_dest, NULL, 4), S2N_ERR_NULL);
    EXPECT_SUCCESS(POSIX_CHECKED_MEMCPY_harness(&POSIX__checked_memcpy_dest, &POSIX__checked_memcpy_source, 4));
    EXPECT_EQUAL(POSIX__checked_memcpy_dest, POSIX__checked_memcpy_source);

    /* POSIX_CHECKED_MEMSET(destination, value, len) */
    uint32_t POSIX__checked_memset_dest = 1;
    EXPECT_SUCCESS(POSIX_CHECKED_MEMSET_harness(&POSIX__checked_memset_dest, 0x42, 0));
    EXPECT_EQUAL(POSIX__checked_memset_dest, 1);
    EXPECT_FAILURE_WITH_ERRNO(POSIX_CHECKED_MEMSET_harness(NULL, 0x42, 1), S2N_ERR_NULL);
    EXPECT_SUCCESS(POSIX_CHECKED_MEMSET_harness(&POSIX__checked_memset_dest, 0x42, 4));
    EXPECT_EQUAL(POSIX__checked_memset_dest, 0x42424242);

    /* POSIX_GUARD(result) */
    EXPECT_SUCCESS(POSIX_GUARD_harness(POSIX_ENSURE_harness(true)));
    EXPECT_FAILURE_WITH_ERRNO(POSIX_GUARD_harness(POSIX_ENSURE_harness(false)), S2N_ERR_SAFETY);

    /* POSIX_GUARD_OSSL(result, error) */
    EXPECT_SUCCESS(POSIX_GUARD_OSSL_harness(1, S2N_ERR_SAFETY));
    EXPECT_FAILURE_WITH_ERRNO(POSIX_GUARD_OSSL_harness(0, S2N_ERR_SAFETY), S2N_ERR_SAFETY);

    /* PTR_BAIL(error) */
    EXPECT_NULL_WITH_ERRNO(PTR_BAIL_harness(), S2N_ERR_SAFETY);

    /* PTR_ENSURE(condition, error) */
    EXPECT_NOT_NULL(PTR_ENSURE_harness(true));
    EXPECT_NULL_WITH_ERRNO(PTR_ENSURE_harness(false), S2N_ERR_SAFETY);

    /* PTR_DEBUG_ENSURE(condition, error) */
    EXPECT_NOT_NULL(PTR_DEBUG_ENSURE_harness(true));
    #ifdef NDEBUG
    EXPECT_NOT_NULL(PTR_DEBUG_ENSURE_harness(false));
    #else
    EXPECT_NULL_WITH_ERRNO(PTR_DEBUG_ENSURE_harness(false), S2N_ERR_SAFETY);
    #endif

    /* PTR_ENSURE_OK(result, error) */
    EXPECT_NOT_NULL(PTR_ENSURE_OK_harness(true));
    EXPECT_NULL_WITH_ERRNO(PTR_ENSURE_OK_harness(false), S2N_ERR_IO);

    /* PTR_ENSURE_GTE(a, b) */
    EXPECT_NOT_NULL(PTR_ENSURE_GTE_harness_uint32(0, 0));
    EXPECT_NOT_NULL(PTR_ENSURE_GTE_harness_uint32(1, 0));
    EXPECT_NULL_WITH_ERRNO(PTR_ENSURE_GTE_harness_uint32(0, 1), S2N_ERR_SAFETY);
    EXPECT_NOT_NULL(PTR_ENSURE_GTE_harness_int32(-1, -2));
    EXPECT_NOT_NULL(PTR_ENSURE_GTE_harness_int32(-1, -1));
    EXPECT_NULL_WITH_ERRNO(PTR_ENSURE_GTE_harness_int32(-2, -1), S2N_ERR_SAFETY);

    /* PTR_ENSURE_LTE(a, b) */
    EXPECT_NOT_NULL(PTR_ENSURE_LTE_harness_uint32(0, 0));
    EXPECT_NOT_NULL(PTR_ENSURE_LTE_harness_uint32(0, 1));
    EXPECT_NULL_WITH_ERRNO(PTR_ENSURE_LTE_harness_uint32(1, 0), S2N_ERR_SAFETY);
    EXPECT_NOT_NULL(PTR_ENSURE_LTE_harness_int32(-2, -1));
    EXPECT_NOT_NULL(PTR_ENSURE_LTE_harness_int32(-1, -1));
    EXPECT_NULL_WITH_ERRNO(PTR_ENSURE_LTE_harness_int32(-1, -2), S2N_ERR_SAFETY);

    /* PTR_ENSURE_GT(a, b) */
    EXPECT_NULL_WITH_ERRNO(PTR_ENSURE_GT_harness_uint32(0, 0), S2N_ERR_SAFETY);
    EXPECT_NOT_NULL(PTR_ENSURE_GT_harness_uint32(1, 0));
    EXPECT_NULL_WITH_ERRNO(PTR_ENSURE_GT_harness_uint32(0, 1), S2N_ERR_SAFETY);
    EXPECT_NOT_NULL(PTR_ENSURE_GT_harness_int32(-1, -2));
    EXPECT_NULL_WITH_ERRNO(PTR_ENSURE_GT_harness_int32(-1, -1), S2N_ERR_SAFETY);
    EXPECT_NULL_WITH_ERRNO(PTR_ENSURE_GT_harness_int32(-2, -1), S2N_ERR_SAFETY);

    /* PTR_ENSURE_LT(a, b) */
    EXPECT_NULL_WITH_ERRNO(PTR_ENSURE_LT_harness_uint32(0, 0), S2N_ERR_SAFETY);
    EXPECT_NOT_NULL(PTR_ENSURE_LT_harness_uint32(0, 1));
    EXPECT_NULL_WITH_ERRNO(PTR_ENSURE_LT_harness_uint32(1, 0), S2N_ERR_SAFETY);
    EXPECT_NOT_NULL(PTR_ENSURE_LT_harness_int32(-2, -1));
    EXPECT_NULL_WITH_ERRNO(PTR_ENSURE_LT_harness_int32(-1, -1), S2N_ERR_SAFETY);
    EXPECT_NULL_WITH_ERRNO(PTR_ENSURE_LT_harness_int32(-1, -2), S2N_ERR_SAFETY);

    /* PTR_ENSURE_EQ(a, b) */
    EXPECT_NOT_NULL(PTR_ENSURE_EQ_harness_uint32(0, 0));
    EXPECT_NULL_WITH_ERRNO(PTR_ENSURE_EQ_harness_uint32(1, 0), S2N_ERR_SAFETY);
    EXPECT_NOT_NULL(PTR_ENSURE_EQ_harness_int32(-1, -1));
    EXPECT_NULL_WITH_ERRNO(PTR_ENSURE_EQ_harness_int32(-2, -1), S2N_ERR_SAFETY);

    /* PTR_ENSURE_NE(a, b) */
    EXPECT_NOT_NULL(PTR_ENSURE_NE_harness_uint32(1, 0));
    EXPECT_NULL_WITH_ERRNO(PTR_ENSURE_NE_harness_uint32(0, 0), S2N_ERR_SAFETY);
    EXPECT_NOT_NULL(PTR_ENSURE_NE_harness_int32(-2, -1));
    EXPECT_NULL_WITH_ERRNO(PTR_ENSURE_NE_harness_int32(-1, -1), S2N_ERR_SAFETY);

    /* PTR_ENSURE_INCLUSIVE_RANGE(min, n, max) */
    EXPECT_NULL_WITH_ERRNO(PTR_ENSURE_INCLUSIVE_RANGE_harness_uint32(1, 0, 2), S2N_ERR_SAFETY);
    EXPECT_NOT_NULL(PTR_ENSURE_INCLUSIVE_RANGE_harness_uint32(1, 1, 2));
    EXPECT_NOT_NULL(PTR_ENSURE_INCLUSIVE_RANGE_harness_uint32(1, 2, 2));
    EXPECT_NULL_WITH_ERRNO(PTR_ENSURE_INCLUSIVE_RANGE_harness_uint32(1, 3, 2), S2N_ERR_SAFETY);
    EXPECT_NULL_WITH_ERRNO(PTR_ENSURE_INCLUSIVE_RANGE_harness_int32(-2, -3, -1), S2N_ERR_SAFETY);
    EXPECT_NOT_NULL(PTR_ENSURE_INCLUSIVE_RANGE_harness_int32(-2, -2, -1));
    EXPECT_NOT_NULL(PTR_ENSURE_INCLUSIVE_RANGE_harness_int32(-2, -1, -1));
    EXPECT_NULL_WITH_ERRNO(PTR_ENSURE_INCLUSIVE_RANGE_harness_int32(-2, 0, -1), S2N_ERR_SAFETY);

    /* PTR_ENSURE_EXCLUSIVE_RANGE(min, n, max) */
    EXPECT_NULL_WITH_ERRNO(PTR_ENSURE_EXCLUSIVE_RANGE_harness_uint32(1, 0, 3), S2N_ERR_SAFETY);
    EXPECT_NULL_WITH_ERRNO(PTR_ENSURE_EXCLUSIVE_RANGE_harness_uint32(1, 1, 3), S2N_ERR_SAFETY);
    EXPECT_NOT_NULL(PTR_ENSURE_EXCLUSIVE_RANGE_harness_uint32(1, 2, 3));
    EXPECT_NULL_WITH_ERRNO(PTR_ENSURE_EXCLUSIVE_RANGE_harness_uint32(1, 3, 3), S2N_ERR_SAFETY);
    EXPECT_NULL_WITH_ERRNO(PTR_ENSURE_EXCLUSIVE_RANGE_harness_uint32(1, 4, 3), S2N_ERR_SAFETY);
    EXPECT_NULL_WITH_ERRNO(PTR_ENSURE_EXCLUSIVE_RANGE_harness_int32(-3, -4, -1), S2N_ERR_SAFETY);
    EXPECT_NULL_WITH_ERRNO(PTR_ENSURE_EXCLUSIVE_RANGE_harness_int32(-3, -3, -1), S2N_ERR_SAFETY);
    EXPECT_NOT_NULL(PTR_ENSURE_EXCLUSIVE_RANGE_harness_int32(-3, -2, -1));
    EXPECT_NULL_WITH_ERRNO(PTR_ENSURE_EXCLUSIVE_RANGE_harness_int32(-3, -1, -1), S2N_ERR_SAFETY);
    EXPECT_NULL_WITH_ERRNO(PTR_ENSURE_EXCLUSIVE_RANGE_harness_int32(-3, 0, -1), S2N_ERR_SAFETY);

    /* PTR_ENSURE_REF(x) */
    EXPECT_NOT_NULL(PTR_ENSURE_REF_harness(""));
    EXPECT_NOT_NULL(PTR_ENSURE_REF_harness("ok"));
    EXPECT_NULL_WITH_ERRNO(PTR_ENSURE_REF_harness(NULL), S2N_ERR_NULL);

    /* PTR_ENSURE_MUT(x) */
    uint32_t PTR_ensure_mut_test = 0;
    EXPECT_NOT_NULL(PTR_ENSURE_MUT_harness(&PTR_ensure_mut_test));
    PTR_ensure_mut_test = 1;
    EXPECT_NOT_NULL(PTR_ENSURE_MUT_harness(&PTR_ensure_mut_test));
    EXPECT_NULL_WITH_ERRNO(PTR_ENSURE_MUT_harness(NULL), S2N_ERR_NULL);

    /* PTR_PRECONDITION(result) */
    EXPECT_NOT_NULL(PTR_PRECONDITION_harness(PTR_PRECONDITION_harness_check(true)));
    EXPECT_NULL_WITH_ERRNO(PTR_PRECONDITION_harness(PTR_PRECONDITION_harness_check(false)), S2N_ERR_SAFETY);

    /* PTR_POSTCONDITION(result) */
    EXPECT_NOT_NULL(PTR_POSTCONDITION_harness(PTR_POSTCONDITION_harness_check(true)));
    #ifdef NDEBUG
    EXPECT_NOT_NULL(PTR_POSTCONDITION_harness(PTR_POSTCONDITION_harness_check(false)));
    #else
    EXPECT_NULL_WITH_ERRNO(PTR_POSTCONDITION_harness(PTR_POSTCONDITION_harness_check(false)), S2N_ERR_SAFETY);
    #endif

    /* PTR_CHECKED_MEMCPY(destination, source, len) */
    uint32_t PTR__checked_memcpy_dest = 1;
    uint32_t PTR__checked_memcpy_source = 2;
    EXPECT_NOT_NULL(PTR_CHECKED_MEMCPY_harness(&PTR__checked_memcpy_dest, &PTR__checked_memcpy_source, 0));
    EXPECT_EQUAL(PTR__checked_memcpy_dest, 1);
    EXPECT_NULL_WITH_ERRNO(PTR_CHECKED_MEMCPY_harness(NULL, &PTR__checked_memcpy_source, 4), S2N_ERR_NULL);
    EXPECT_NULL_WITH_ERRNO(PTR_CHECKED_MEMCPY_harness(&PTR__checked_memcpy_dest, NULL, 4), S2N_ERR_NULL);
    EXPECT_NOT_NULL(PTR_CHECKED_MEMCPY_harness(&PTR__checked_memcpy_dest, &PTR__checked_memcpy_source, 4));
    EXPECT_EQUAL(PTR__checked_memcpy_dest, PTR__checked_memcpy_source);

    /* PTR_CHECKED_MEMSET(destination, value, len) */
    uint32_t PTR__checked_memset_dest = 1;
    EXPECT_NOT_NULL(PTR_CHECKED_MEMSET_harness(&PTR__checked_memset_dest, 0x42, 0));
    EXPECT_EQUAL(PTR__checked_memset_dest, 1);
    EXPECT_NULL_WITH_ERRNO(PTR_CHECKED_MEMSET_harness(NULL, 0x42, 1), S2N_ERR_NULL);
    EXPECT_NOT_NULL(PTR_CHECKED_MEMSET_harness(&PTR__checked_memset_dest, 0x42, 4));
    EXPECT_EQUAL(PTR__checked_memset_dest, 0x42424242);

    /* PTR_GUARD(result) */
    EXPECT_NOT_NULL(PTR_GUARD_harness(PTR_ENSURE_harness(true)));
    EXPECT_NULL_WITH_ERRNO(PTR_GUARD_harness(PTR_ENSURE_harness(false)), S2N_ERR_SAFETY);

    /* PTR_GUARD_OSSL(result, error) */
    EXPECT_NOT_NULL(PTR_GUARD_OSSL_harness(1, S2N_ERR_SAFETY));
    EXPECT_NULL_WITH_ERRNO(PTR_GUARD_OSSL_harness(0, S2N_ERR_SAFETY), S2N_ERR_SAFETY);


    END_TEST();
    return S2N_SUCCESS;
}
