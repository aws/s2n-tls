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

    /* s2n_connection_calculate_blinding */
    {
        DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT), s2n_connection_ptr_free);
        EXPECT_NOT_NULL(conn);
        EXPECT_NOT_NULL(conn->config);

        for (size_t i = 0; i <= 30; i++) {
            conn->config->max_blinding = i;
            int64_t min = 0;
            int64_t max = 0;

            EXPECT_OK(s2n_connection_calculate_blinding(conn, &min, &max));
            if (i == 0) {
                EXPECT_EQUAL(max, S2N_DEFAULT_BLINDING_CEILING * ONE_S);
                EXPECT_EQUAL(min, S2N_DEFAULT_BLINDING_FLOOR * ONE_S);
            } else {
                EXPECT_EQUAL(max, i * ONE_S);
                EXPECT_EQUAL(min, i * ONE_S / 3);

                /* We _never_ want zero blinding */
                EXPECT_NOT_EQUAL(max, 0);
                EXPECT_NOT_EQUAL(min, 0);
            }
        }
    }

    END_TEST();
    return 0;
}
