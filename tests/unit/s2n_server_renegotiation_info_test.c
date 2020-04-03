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

#include <stdint.h>

#include "tls/s2n_config.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_tls.h"
#include "tls/s2n_tls13.h"
#include "tls/extensions/s2n_server_renegotiation_info.h"

#include "stuffer/s2n_stuffer.h"
#include "utils/s2n_safety.h"

int main(int argc, char **argv)
{
    BEGIN_TEST();

    struct s2n_config *config;
    EXPECT_NOT_NULL(config = s2n_config_new());

    /* Test server_renegotiation_info send and recv */
    {
        struct s2n_connection *server_conn, *client_conn;
        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
        EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config));

       /* Zero length extension expected as conn cannot send ext */
        EXPECT_EQUAL(0, s2n_server_renegotiation_info_ext_size(server_conn));

        /* Set connection to be able to send extension and verify size */
        uint16_t expected_ext_length = 5;

        server_conn->actual_protocol_version = S2N_TLS12;
        server_conn->secure_renegotiation = 1;
        EXPECT_EQUAL(expected_ext_length, s2n_server_renegotiation_info_ext_size(server_conn));

        struct s2n_stuffer extension;
        s2n_stuffer_alloc(&extension, s2n_server_renegotiation_info_ext_size(server_conn));

        EXPECT_SUCCESS(s2n_send_server_renegotiation_info_ext(server_conn, &extension));
        EXPECT_EQUAL(s2n_stuffer_data_available(&extension), s2n_server_renegotiation_info_ext_size(server_conn));

        uint16_t extension_type, extension_length;
        s2n_stuffer_read_uint16(&extension, &extension_type);
        s2n_stuffer_read_uint16(&extension, &extension_length);
        EXPECT_EQUAL(extension_type, TLS_EXTENSION_RENEGOTIATION_INFO);
        EXPECT_EQUAL(extension_length, 1);
        EXPECT_EQUAL(s2n_stuffer_data_available(&extension), extension_length);

        EXPECT_SUCCESS(s2n_recv_server_renegotiation_info_ext(client_conn, &extension));
        EXPECT_EQUAL(client_conn->secure_renegotiation, 1);

        EXPECT_SUCCESS(s2n_stuffer_free(&extension));
        EXPECT_SUCCESS(s2n_connection_free(client_conn));
        EXPECT_SUCCESS(s2n_connection_free(server_conn));
    }

    EXPECT_SUCCESS(s2n_config_free(config));

    END_TEST();
    return 0;
}
