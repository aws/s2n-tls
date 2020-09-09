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
#include "tls/s2n_quic_support.h"

#include "tls/s2n_connection.h"

int main(int argc, char **argv)
{
    BEGIN_TEST();

    /* Test s2n_connection_enable_quic */
    {
        struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT);
        EXPECT_NOT_NULL(conn);
        EXPECT_FALSE(conn->quic_enabled);

        /* Check error handling */
        {
            EXPECT_SUCCESS(s2n_disable_tls13());
            EXPECT_SUCCESS(s2n_in_unit_test_set(true));
            EXPECT_FAILURE_WITH_ERRNO(s2n_connection_enable_quic(conn), S2N_ERR_PROTOCOL_VERSION_UNSUPPORTED);
            EXPECT_FALSE(conn->quic_enabled);

            EXPECT_SUCCESS(s2n_enable_tls13());
            EXPECT_SUCCESS(s2n_in_unit_test_set(true));
            EXPECT_FAILURE_WITH_ERRNO(s2n_connection_enable_quic(NULL), S2N_ERR_NULL);
            EXPECT_FALSE(conn->quic_enabled);

            EXPECT_SUCCESS(s2n_enable_tls13());
            EXPECT_SUCCESS(s2n_in_unit_test_set(false));
            EXPECT_FAILURE_WITH_ERRNO(s2n_connection_enable_quic(conn), S2N_ERR_NOT_IN_TEST);
            EXPECT_FALSE(conn->quic_enabled);
        }

        /* Check success */
        {
            EXPECT_SUCCESS(s2n_enable_tls13());
            EXPECT_SUCCESS(s2n_in_unit_test_set(true));
            EXPECT_SUCCESS(s2n_connection_enable_quic(conn));
            EXPECT_TRUE(conn->quic_enabled);

            /* Enabling QUIC again still succeeds */
            EXPECT_SUCCESS(s2n_connection_enable_quic(conn));
            EXPECT_TRUE(conn->quic_enabled);
        }

        EXPECT_SUCCESS(s2n_connection_free(conn));
    }

    END_TEST();
}
