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
#include "tls/s2n_alerts.h"
#include "tls/s2n_shutdown.c"

#define ALERT_LEN (sizeof(uint16_t))

int mock_send_impl(void *io_context, const uint8_t *buf, uint32_t len)
{
    return len;
}

int main(int argc, char **argv)
{
    BEGIN_TEST();

    const uint8_t close_notify_alert[] = {  2 /* AlertLevel = fatal */,
                                            0 /* AlertDescription = close_notify */ };

    /* Test s2n_shutdown */
    {

        /* If send and recv impl are NULL always proceed with shutdown  */
        {
            struct s2n_config *config;
            EXPECT_NOT_NULL(config = s2n_config_new());
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));
            EXPECT_SUCCESS(s2n_connection_set_config(conn, config));

            /* Verify state prior to alert */
            EXPECT_FALSE(conn->did_recv_close_notify);

            /* Write and process the alert */
            EXPECT_SUCCESS(s2n_stuffer_write_bytes(&conn->in, close_notify_alert, sizeof(close_notify_alert)));
            EXPECT_SUCCESS(s2n_process_alert_fragment(conn));

            /* Verify state after alert */
            EXPECT_TRUE(conn->did_recv_close_notify);

            s2n_blocked_status blocked;
            EXPECT_SUCCESS(s2n_shutdown(conn, &blocked));

            EXPECT_SUCCESS(s2n_connection_free(conn));
            EXPECT_SUCCESS(s2n_config_free(config));
        }

        /* Await close_notify if did_recv_close_notify is not set */
        {
            struct s2n_config *config;
            EXPECT_NOT_NULL(config = s2n_config_new());
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));
            EXPECT_SUCCESS(s2n_connection_set_config(conn, config));

            /* Set mock send impl */
            EXPECT_SUCCESS(s2n_connection_set_send_cb(conn, &mock_send_impl));

            /* Verify state prior to alert */
            EXPECT_FALSE(conn->did_recv_close_notify);

            s2n_blocked_status blocked;
            EXPECT_FAILURE_WITH_ERRNO(s2n_shutdown(conn, &blocked), S2N_ERR_IO);
            EXPECT_EQUAL(blocked, S2N_BLOCKED_ON_READ);

            /* Verify state after shutdown attempt */
            EXPECT_FALSE(conn->did_recv_close_notify);

            EXPECT_SUCCESS(s2n_connection_free(conn));
            EXPECT_SUCCESS(s2n_config_free(config));
        }

        /* Do not await close_notify if did_recv_close_notify is set */
        {
            struct s2n_config *config;
            EXPECT_NOT_NULL(config = s2n_config_new());
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));
            EXPECT_SUCCESS(s2n_connection_set_config(conn, config));

            /* Set mock send impl */
            EXPECT_SUCCESS(s2n_connection_set_send_cb(conn, &mock_send_impl));

            /* Verify state prior to alert */
            EXPECT_FALSE(conn->did_recv_close_notify);

            /* Write and process the alert */
            EXPECT_SUCCESS(s2n_stuffer_write_bytes(&conn->in, close_notify_alert, sizeof(close_notify_alert)));
            EXPECT_SUCCESS(s2n_process_alert_fragment(conn));

            /* Verify state after alert */
            EXPECT_TRUE(conn->did_recv_close_notify);

            s2n_blocked_status blocked;
            EXPECT_SUCCESS(s2n_shutdown(conn, &blocked));
            EXPECT_EQUAL(blocked, S2N_NOT_BLOCKED);

            /* Verify state after shutdown attempt */
            EXPECT_TRUE(conn->did_recv_close_notify);

            EXPECT_SUCCESS(s2n_connection_free(conn));
            EXPECT_SUCCESS(s2n_config_free(config));
        }

    }

    END_TEST();
}
