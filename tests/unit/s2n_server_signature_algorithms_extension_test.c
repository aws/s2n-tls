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

#include <stdint.h>

#include "s2n_test.h"
#include "stuffer/s2n_stuffer.h"
#include "testlib/s2n_testlib.h"
#include "tls/extensions/s2n_server_signature_algorithms.h"
#include "tls/s2n_config.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_tls.h"
#include "tls/s2n_tls13.h"
#include "utils/s2n_safety.h"

int main(int argc, char **argv)
{
    BEGIN_TEST();

    s2n_enable_tls13_in_test();

    {
        struct s2n_connection *client_conn;
        struct s2n_connection *server_conn;
        EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));

        struct s2n_stuffer io = { 0 };
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&io, 0));

        EXPECT_SUCCESS(s2n_server_signature_algorithms_extension.send(server_conn, &io));
        EXPECT_SUCCESS(s2n_server_signature_algorithms_extension.recv(client_conn, &io));
        EXPECT_EQUAL(s2n_stuffer_data_available(&io), 0);

        EXPECT_TRUE(client_conn->handshake_params.server_sig_hash_algs.len > 0);

        s2n_stuffer_free(&io);
        EXPECT_SUCCESS(s2n_connection_free(server_conn));
        EXPECT_SUCCESS(s2n_connection_free(client_conn));
    };

    s2n_disable_tls13_in_test();

    END_TEST();

    return 0;
}
