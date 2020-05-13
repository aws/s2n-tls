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

#include "tls/s2n_connection.h"

const uint8_t actual_version = 1, client_version = 2, server_version = 3;
static int s2n_set_test_protocol_versions(struct s2n_connection *conn)
{
    conn->actual_protocol_version = actual_version;
    conn->client_protocol_version = client_version;
    conn->server_protocol_version = server_version;
    return S2N_SUCCESS;
}

int main(int argc, char **argv)
{
    BEGIN_TEST();

    /* s2n_connection_get_protocol_version */
    {
        struct s2n_connection *client_conn, *server_conn;
        EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
        EXPECT_SUCCESS(s2n_set_test_protocol_versions(client_conn));
        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
        EXPECT_SUCCESS(s2n_set_test_protocol_versions(server_conn));

        /* Return actual if set */
        EXPECT_EQUAL(s2n_connection_get_protocol_version(client_conn), actual_version);
        EXPECT_EQUAL(s2n_connection_get_protocol_version(server_conn), actual_version);

        /* If actual version not set, result version for mode */
        client_conn->actual_protocol_version = S2N_UNKNOWN_PROTOCOL_VERSION;
        EXPECT_EQUAL(s2n_connection_get_protocol_version(client_conn), client_version);
        server_conn->actual_protocol_version = S2N_UNKNOWN_PROTOCOL_VERSION;
        EXPECT_EQUAL(s2n_connection_get_protocol_version(server_conn), server_version);

        EXPECT_SUCCESS(s2n_connection_free(client_conn));
        EXPECT_SUCCESS(s2n_connection_free(server_conn));
    }

    END_TEST();
}
