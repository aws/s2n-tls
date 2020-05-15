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

#include "tls/extensions/s2n_client_renegotiation_info.h"

int main(int argc, char **argv)
{
    BEGIN_TEST();

    /* Test receive - too much data */
    {
        struct s2n_connection *conn;
        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));

        struct s2n_stuffer stuffer;
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&stuffer, 0));

        EXPECT_SUCCESS(s2n_stuffer_write_uint16(&stuffer, 0));

        EXPECT_FAILURE_WITH_ERRNO(s2n_client_renegotiation_info_extension.recv(conn, &stuffer),
                S2N_ERR_NON_EMPTY_RENEGOTIATION_INFO);
        EXPECT_FALSE(conn->secure_renegotiation);

        EXPECT_SUCCESS(s2n_stuffer_free(&stuffer));
        EXPECT_SUCCESS(s2n_connection_free(conn));
    }

    /* Test receive - value not 0 */
    {
        struct s2n_connection *conn;
        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));

        struct s2n_stuffer stuffer;
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&stuffer, 0));

        EXPECT_SUCCESS(s2n_stuffer_write_uint8(&stuffer, 1));

        EXPECT_FAILURE_WITH_ERRNO(s2n_client_renegotiation_info_extension.recv(conn, &stuffer),
                S2N_ERR_NON_EMPTY_RENEGOTIATION_INFO);
        EXPECT_FALSE(conn->secure_renegotiation);

        EXPECT_SUCCESS(s2n_stuffer_free(&stuffer));
        EXPECT_SUCCESS(s2n_connection_free(conn));
    }

    /* Test receive */
    {
        struct s2n_connection *conn;
        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));

        struct s2n_stuffer stuffer;
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&stuffer, 0));

        EXPECT_SUCCESS(s2n_stuffer_write_uint8(&stuffer, 0));

        EXPECT_SUCCESS(s2n_client_renegotiation_info_extension.recv(conn, &stuffer));
        EXPECT_TRUE(conn->secure_renegotiation);

        EXPECT_SUCCESS(s2n_stuffer_free(&stuffer));
        EXPECT_SUCCESS(s2n_connection_free(conn));
    }

    END_TEST();
}
