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

S2N_RESULT s2n_connection_calculate_blinding(struct s2n_connection *conn, int64_t *min, int64_t *max);

int main(int argc, char **argv)
{
    BEGIN_TEST();

    /* s2n_connection_calculate_blinding */
    {
        DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT), s2n_connection_ptr_free);
        EXPECT_NOT_NULL(conn);

        for (size_t i = 0; i <= 30; i++) {
            conn->max_blinding = i;
            int64_t min = 0;
            int64_t max = 0;

            EXPECT_OK(s2n_connection_calculate_blinding(conn, &min, &max));
            if (i == 0) {
                EXPECT_EQUAL(max, DEFAULT_BLINDING_CEILING * ONE_S);
                EXPECT_EQUAL(min, DEFAULT_BLINDING_FLOOR * ONE_S);
            } else {
                EXPECT_EQUAL(max, i * ONE_S);
                EXPECT_EQUAL(min, i * ONE_S / 3);
            }
        }
    }

    /* s2n_connection_set_max_blinding */
    {
        DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT), s2n_connection_ptr_free);
        EXPECT_NOT_NULL(conn);

        for (size_t i = 0; i <= DEFAULT_BLINDING_CEILING + 1; i++) {
            if (i == 0 || i > DEFAULT_BLINDING_CEILING) {
                EXPECT_FAILURE_WITH_ERRNO(s2n_connection_set_max_blinding(conn, i), S2N_ERR_INVALID_ARGUMENT);
            } else {
                EXPECT_SUCCESS(s2n_connection_set_max_blinding(conn, i));
                EXPECT_EQUAL(conn->max_blinding, i);
            }
        }
    }

    END_TEST();
    return 0;
}
