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
#include "tls/s2n_record.h"
#include "tls/s2n_tls.h"
#include "utils/s2n_safety.h"

int main(int argc, char *argv[])
{
    BEGIN_TEST();

    /* Test: Records sent before the ServerHello include a sane protocol version */
    {
        const uint8_t expected_version = S2N_TLS10;

        /* Test: ClientHellos include a sane protocol version */
        {
            DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT),
                    s2n_connection_ptr_free);
            EXPECT_NOT_NULL(client_conn);

            DEFER_CLEANUP(struct s2n_stuffer out = { 0 }, s2n_stuffer_free);
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&out, 0));
            EXPECT_SUCCESS(s2n_connection_set_send_io_stuffer(&out, client_conn));

            s2n_blocked_status blocked = S2N_NOT_BLOCKED;
            EXPECT_OK(s2n_negotiate_until_message(client_conn, &blocked, SERVER_HELLO));

            uint8_t content_type = 0;
            EXPECT_SUCCESS(s2n_stuffer_read_uint8(&out, &content_type));
            EXPECT_EQUAL(content_type, TLS_HANDSHAKE);

            uint8_t version_high = 0;
            EXPECT_SUCCESS(s2n_stuffer_read_uint8(&out, &version_high));
            EXPECT_EQUAL(version_high, expected_version / 10);

            uint8_t version_low = 0;
            EXPECT_SUCCESS(s2n_stuffer_read_uint8(&out, &version_low));
            EXPECT_EQUAL(version_low, expected_version % 10);
        }

        /* Test: Alerts include a sane protocol version */
        {
            DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            EXPECT_NOT_NULL(server_conn);

            DEFER_CLEANUP(struct s2n_stuffer out = { 0 }, s2n_stuffer_free);
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&out, 0));
            EXPECT_SUCCESS(s2n_connection_set_send_io_stuffer(&out, server_conn));

            s2n_blocked_status blocked = S2N_NOT_BLOCKED;
            EXPECT_SUCCESS(s2n_shutdown_send(server_conn, &blocked));

            uint8_t content_type = 0;
            EXPECT_SUCCESS(s2n_stuffer_read_uint8(&out, &content_type));
            EXPECT_EQUAL(content_type, TLS_ALERT);

            uint8_t version_high = 0;
            EXPECT_SUCCESS(s2n_stuffer_read_uint8(&out, &version_high));
            EXPECT_EQUAL(version_high, expected_version / 10);

            uint8_t version_low = 0;
            EXPECT_SUCCESS(s2n_stuffer_read_uint8(&out, &version_low));
            EXPECT_EQUAL(version_low, expected_version % 10);
        }
    }

    END_TEST();
}
