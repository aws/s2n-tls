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

#include "s2n_test.h"
#include "testlib/s2n_testlib.h"

#define ONE_S INT64_C(1000000000)

S2N_RESULT s2n_connection_calculate_blinding(struct s2n_connection *conn, int64_t *min, int64_t *max);

int main(int argc, char **argv)
{
    BEGIN_TEST();

    struct {
        uint32_t custom_blinding;
        uint64_t expected_min;
        uint64_t expected_max;
    } test_cases[] = {
        { .custom_blinding = 0, .expected_min = 0, .expected_max = 0 },
        { .custom_blinding = 1, .expected_min = 333333333, .expected_max = 1000000000 },
        { .custom_blinding = 3, .expected_min = 1000000000, .expected_max = 3000000000 },
        { .custom_blinding = 30, .expected_min = S2N_DEFAULT_BLINDING_MIN * ONE_S, .expected_max = S2N_DEFAULT_BLINDING_MAX * ONE_S },
        { .custom_blinding = UINT32_MAX, .expected_min = 1431655765000000000, .expected_max = 4294967295000000000 },
    };

    /* s2n_connection_calculate_blinding */
    {
        DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT), s2n_connection_ptr_free);
        EXPECT_NOT_NULL(conn);
        EXPECT_NOT_NULL(conn->config);

        int64_t min = 0;
        int64_t max = 0;

        /* The default max blinding delay is 10-30 seconds */
        EXPECT_OK(s2n_connection_calculate_blinding(conn, &min, &max));
        EXPECT_EQUAL(min, S2N_DEFAULT_BLINDING_MIN * ONE_S);
        EXPECT_EQUAL(max, S2N_DEFAULT_BLINDING_MAX * ONE_S);

        for (size_t i = 0; i < s2n_array_len(test_cases); i++) {
            EXPECT_SUCCESS(s2n_config_set_max_blinding_delay(conn->config, test_cases[i].custom_blinding));

            min = 0;
            max = 0;
            EXPECT_OK(s2n_connection_calculate_blinding(conn, &min, &max));

            EXPECT_EQUAL(min, test_cases[i].expected_min);
            EXPECT_EQUAL(max, test_cases[i].expected_max);
        }
    }

    END_TEST();
    return 0;
}
