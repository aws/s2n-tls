/*
 * Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

#include "tls/s2n_tls.h"
#include "tls/s2n_config.h"
#include "tls/s2n_connection.h"

int main(int argc, char **argv)
{
    BEGIN_TEST();

    /* Client does not use TLS 1.3 by default */
    {
        struct s2n_connection *conn;
        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));

        EXPECT_NOT_EQUAL(conn->client_protocol_version, S2N_TLS13);

        EXPECT_SUCCESS(s2n_connection_free(conn));
    }

    /* Server does not use TLS 1.3 by default */
    {
        struct s2n_connection *conn;
        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));

        EXPECT_NOT_EQUAL(conn->server_protocol_version, S2N_TLS13);

        EXPECT_SUCCESS(s2n_connection_free(conn));
    }

    EXPECT_SUCCESS(setenv("S2N_ENABLE_TLS13_FOR_TESTING", "1", 0));

    /* Client does use TLS 1.3 if enabled */
    {
        struct s2n_connection *conn;
        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));

        EXPECT_EQUAL(conn->client_protocol_version, S2N_TLS13);

        EXPECT_SUCCESS(s2n_connection_free(conn));
    }

    /* Server does use TLS 1.3 if enabled */
    {
        struct s2n_connection *conn;
        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));

        EXPECT_EQUAL(conn->server_protocol_version, S2N_TLS13);

        EXPECT_SUCCESS(s2n_connection_free(conn));
    }

    END_TEST();
    return 0;
}
