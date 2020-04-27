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
#include <s2n.h>
#include "tls/s2n_connection.h"

int main(int argc, char **argv) {
    BEGIN_TEST();

    /* Test an overflow in s2n_connection_get_session_length() */
    {
        struct s2n_connection *conn;
        struct s2n_config *config;

        conn = s2n_connection_new(S2N_CLIENT);
        config = s2n_config_new();
        s2n_connection_set_config(conn, config);

        config->use_tickets = true;
        conn->client_ticket.size = UINT32_MAX;

        EXPECT_FAILURE(s2n_connection_get_session_length(conn));
    }

    END_TEST();
}

