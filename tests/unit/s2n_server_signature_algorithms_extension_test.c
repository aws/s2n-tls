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

#include <stdint.h>

#include "tls/s2n_config.h"
#include "tls/s2n_connection.h"
#include "tls/extensions/s2n_server_signature_algorithms.h"
#include "tls/s2n_tls.h"
#include "tls/s2n_tls13.h"

#include "stuffer/s2n_stuffer.h"
#include "utils/s2n_safety.h"

int main(int argc, char **argv)
{
    BEGIN_TEST();

    s2n_enable_tls13();

    {
        struct s2n_connection *client_conn;
        struct s2n_connection *server_conn;
        EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));

        struct s2n_stuffer io;
        s2n_stuffer_alloc(&io, s2n_extensions_server_signature_algorithms_size(server_conn));
        EXPECT_SUCCESS(s2n_extensions_server_signature_algorithms_send(server_conn, &io));

        uint16_t extension_type;
        EXPECT_SUCCESS(s2n_stuffer_read_uint16(&io, &extension_type));
        EXPECT_EQUAL(extension_type, TLS_EXTENSION_SIGNATURE_ALGORITHMS);

        uint16_t extension_size;
        EXPECT_SUCCESS(s2n_stuffer_read_uint16(&io, &extension_size));
        EXPECT_EQUAL(extension_size, s2n_stuffer_data_available(&io));

        EXPECT_SUCCESS(s2n_extensions_server_signature_algorithms_recv(client_conn, &io));
        EXPECT_EQUAL(s2n_stuffer_data_available(&io), 0);

        EXPECT_EQUAL(client_conn->handshake_params.server_sig_hash_algs.len, s2n_supported_sig_schemes_count(server_conn));

        s2n_stuffer_free(&io);
        EXPECT_SUCCESS(s2n_connection_free(server_conn));
        EXPECT_SUCCESS(s2n_connection_free(client_conn));
    }

    s2n_disable_tls13();

    END_TEST();

    return 0;
}
