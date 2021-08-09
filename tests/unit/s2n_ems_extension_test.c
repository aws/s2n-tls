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

#include "tls/extensions/s2n_ems.h"

int main(int argc, char **argv)
{
    BEGIN_TEST();

    /* s2n_server_ems_should_send */
    {
        struct s2n_connection *conn = s2n_connection_new(S2N_SERVER);
        EXPECT_NOT_NULL(conn);

        /* Protocol version is too high */
        conn->actual_protocol_version = S2N_TLS13;
        EXPECT_FALSE(s2n_server_ems_extension.should_send(conn));

        /* Protocol version is less than TLS1.3 */
        conn->actual_protocol_version = S2N_TLS12;
        EXPECT_TRUE(s2n_server_ems_extension.should_send(conn));

        EXPECT_SUCCESS(s2n_connection_free(conn));
    }

    END_TEST();
}
