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

#include <stdbool.h>
#include <sys/wait.h>

#include "api/s2n.h"
#include "s2n_test.h"
#include "utils/s2n_mem.h"
#include "utils/s2n_safety.h"

#define S2N_UNUSED(x) \
    do {              \
        (void) x;     \
    } while (0)

struct foo {
    int x;
    int y;
};

int foo_cleanup_calls;

void foo_free(struct foo* p)
{
    foo_cleanup_calls++;
}

DEFINE_POINTER_CLEANUP_FUNC(struct foo*, foo_free);

int check_cleanup_obj_on_fn_exit()
{
    DEFER_CLEANUP(struct foo x = { 0 }, foo_free);
    S2N_UNUSED(x);
    return 0;
}

int check_cleanup_pointer_on_fn_exit()
{
    struct foo thefoo = { 0 };
    DEFER_CLEANUP(struct foo* foop = &thefoo, foo_free_pointer);
    S2N_UNUSED(thefoo);
    S2N_UNUSED(foop);
    return 0;
}

/* check that our macros don't cleanup null objects */
int check_dont_cleanup_null_on_fn_exit()
{
    DEFER_CLEANUP(struct foo* foop = NULL, foo_free_pointer);
    S2N_UNUSED(foop);
    return 0;
}

/* This test checks that the compiler correctly implements deferred cleanup */
int main()
{
    BEGIN_TEST();
    EXPECT_SUCCESS(s2n_disable_tls13_in_test());
    int expected_cleanup_count = 0;

    /* check that the cleanup functions are called on each loop exit */
    for (int i = 0; i < 10; ++i) {
        DEFER_CLEANUP(struct foo x = { i }, foo_free);
        S2N_UNUSED(x);
        EXPECT_EQUAL(foo_cleanup_calls, expected_cleanup_count);
        expected_cleanup_count++;
    }

    EXPECT_EQUAL(foo_cleanup_calls, expected_cleanup_count);

    EXPECT_SUCCESS(check_cleanup_obj_on_fn_exit());
    expected_cleanup_count++;
    EXPECT_EQUAL(foo_cleanup_calls, expected_cleanup_count);

    EXPECT_SUCCESS(check_cleanup_pointer_on_fn_exit());
    expected_cleanup_count++;
    EXPECT_EQUAL(foo_cleanup_calls, expected_cleanup_count);

    EXPECT_SUCCESS(check_dont_cleanup_null_on_fn_exit());
    /* don't increment expected_cleanup_count */
    EXPECT_EQUAL(foo_cleanup_calls, expected_cleanup_count);

    END_TEST();
}
