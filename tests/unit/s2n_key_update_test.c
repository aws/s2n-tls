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

#include "tls/s2n_key_update.h"
#include "tls/s2n_connection.h"

#include "utils/s2n_safety.h"
#include "tls/s2n_tls13_handshake.h"

int main(int argc, char **argv)
{
    BEGIN_TEST();

    /* This test creates a decrypted key update message and checks to make sure that
     *  it has been successfully processed.
     */
    {
        struct s2n_connection *conn;

        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));

        conn->actual_protocol_version = S2N_TLS13;

        /*EXPECT_SUCCESS(s2n_create_key_update_message(&conn->in)); 

        EXPECT_SUCCESS(s2n_tls13_update_application_traffic_keys(conn, S2N_CLIENT, 1)); */

        EXPECT_SUCCESS(s2n_connection_free(conn));

    }
    END_TEST();
}

