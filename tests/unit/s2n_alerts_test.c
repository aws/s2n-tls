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

#include "tls/s2n_quic_support.h"

#define ALERT_LEN (sizeof(uint16_t))

int main(int argc, char **argv)
{
    BEGIN_TEST();

    /* Test S2N_TLS_ALERT_CLOSE_NOTIFY and close_notify_received */
    {
        const uint8_t close_notify_alert[] = {  2 /* AlertLevel = fatal */,
                                                0 /* AlertDescription = close_notify */ };

        const uint8_t not_close_notify_alert[] = {  2 /* AlertLevel = fatal */,
                                                   10 /* AlertDescription = unexpected_msg */ };


        /* Don't mark close_notify_received = true if we receive an alert other than close_notify alert */
        {
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));

            /* Verify state prior to alert */
            EXPECT_FALSE(conn->close_notify_received);

            /* Write and process the alert */
            EXPECT_SUCCESS(s2n_stuffer_write_bytes(&conn->in, not_close_notify_alert, sizeof(not_close_notify_alert)));

            /* This fails due to the alert. This is ok since we are only testing that close_notify_received was set */
            EXPECT_FAILURE_WITH_ERRNO(s2n_process_alert_fragment(conn), S2N_ERR_ALERT);

            /* Verify state after alert */
            EXPECT_FALSE(conn->close_notify_received);

            EXPECT_SUCCESS(s2n_connection_free(conn));
        }

        /* Mark close_notify_received = true if we receive a close_notify alert */
        {
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));

            /* Verify state prior to alert */
            EXPECT_FALSE(conn->close_notify_received);

            /* Write and process the alert */
            EXPECT_SUCCESS(s2n_stuffer_write_bytes(&conn->in, close_notify_alert, sizeof(close_notify_alert)));
            EXPECT_SUCCESS(s2n_process_alert_fragment(conn));

            /* Verify state after alert */
            EXPECT_TRUE(conn->close_notify_received);

            EXPECT_SUCCESS(s2n_connection_free(conn));
        }

    }

    /* Test s2n_process_alert_fragment */
    {
        /* Safety check */
        EXPECT_FAILURE_WITH_ERRNO(s2n_process_alert_fragment(NULL), S2N_ERR_NULL);

        /* Fails if alerts not supported */
        {
            struct s2n_config *config;
            EXPECT_NOT_NULL(config = s2n_config_new());

            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));
            EXPECT_SUCCESS(s2n_connection_set_config(conn, config));

            /* Succeeds by default */
            EXPECT_SUCCESS(s2n_stuffer_write_uint16(&conn->in, 0));
            EXPECT_SUCCESS(s2n_process_alert_fragment(conn));

            /* Wipe error */
            EXPECT_SUCCESS(s2n_stuffer_wipe(&conn->alert_in));

            /* Fails when alerts not supported (when QUIC mode enabled) */
            EXPECT_SUCCESS(s2n_config_enable_quic(config));
            EXPECT_SUCCESS(s2n_stuffer_write_uint16(&conn->in, 0));
            EXPECT_FAILURE_WITH_ERRNO(s2n_process_alert_fragment(conn), S2N_ERR_BAD_MESSAGE);

            EXPECT_SUCCESS(s2n_connection_free(conn));
            EXPECT_SUCCESS(s2n_config_free(config));
        }

        /* Test warning behavior */
        {
            const uint8_t warning_alert[] = {  1 /* AlertLevel = warning */,
                                              70 /* AlertDescription = protocol_version (arbitrary value) */};

            const uint8_t user_canceled_alert[] = {  1 /* AlertLevel = warning */,
                                                    90 /* AlertDescription = user_canceled */ };

            /* Warnings treated as errors by default in TLS1.2 */
            {
                struct s2n_connection *conn;
                EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));
                EXPECT_EQUAL(conn->config->alert_behavior, S2N_ALERT_FAIL_ON_WARNINGS);
                conn->actual_protocol_version = S2N_TLS12;

                EXPECT_SUCCESS(s2n_stuffer_write_bytes(&conn->in, warning_alert, sizeof(warning_alert)));

                EXPECT_FAILURE_WITH_ERRNO(s2n_process_alert_fragment(conn), S2N_ERR_ALERT);
                EXPECT_TRUE(conn->closed);

                EXPECT_SUCCESS(s2n_connection_free(conn));
            }

            /* Warnings treated as errors by default in TLS1.3 */
            {
                struct s2n_connection *conn;
                EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));
                EXPECT_EQUAL(conn->config->alert_behavior, S2N_ALERT_FAIL_ON_WARNINGS);
                conn->actual_protocol_version = S2N_TLS13;

                EXPECT_SUCCESS(s2n_stuffer_write_bytes(&conn->in, warning_alert, sizeof(warning_alert)));

                EXPECT_FAILURE_WITH_ERRNO(s2n_process_alert_fragment(conn), S2N_ERR_ALERT);
                EXPECT_TRUE(conn->closed);

                EXPECT_SUCCESS(s2n_connection_free(conn));
            }

            /* Warnings ignored in TLS1.2 if alert_behavior == S2N_ALERT_IGNORE_WARNINGS */
            {
                struct s2n_config *config;
                EXPECT_NOT_NULL(config = s2n_config_new());
                EXPECT_SUCCESS(s2n_config_set_alert_behavior(config, S2N_ALERT_IGNORE_WARNINGS));

                struct s2n_connection *conn;
                EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));
                EXPECT_SUCCESS(s2n_connection_set_config(conn, config));
                conn->actual_protocol_version = S2N_TLS12;

                EXPECT_SUCCESS(s2n_stuffer_write_bytes(&conn->in, warning_alert, sizeof(warning_alert)));

                EXPECT_SUCCESS(s2n_process_alert_fragment(conn));
                EXPECT_FALSE(conn->closed);

                EXPECT_SUCCESS(s2n_connection_free(conn));
                EXPECT_SUCCESS(s2n_config_free(config));
            }

            /* Warnings treated as errors in TLS1.3 if alert_behavior == S2N_ALERT_IGNORE_WARNINGS */
            {
                struct s2n_config *config;
                EXPECT_NOT_NULL(config = s2n_config_new());
                EXPECT_SUCCESS(s2n_config_set_alert_behavior(config, S2N_ALERT_IGNORE_WARNINGS));

                struct s2n_connection *conn;
                EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));
                EXPECT_SUCCESS(s2n_connection_set_config(conn, config));
                conn->actual_protocol_version = S2N_TLS13;

                EXPECT_SUCCESS(s2n_stuffer_write_bytes(&conn->in, warning_alert, sizeof(warning_alert)));

                EXPECT_FAILURE_WITH_ERRNO(s2n_process_alert_fragment(conn), S2N_ERR_ALERT);
                EXPECT_TRUE(conn->closed);

                EXPECT_SUCCESS(s2n_connection_free(conn));
                EXPECT_SUCCESS(s2n_config_free(config));
            }

            /* user_canceled ignored in TLS1.3 by default */
            {
                struct s2n_config *config;
                EXPECT_NOT_NULL(config = s2n_config_new());

                struct s2n_connection *conn;
                EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));
                EXPECT_SUCCESS(s2n_connection_set_config(conn, config));
                conn->actual_protocol_version = S2N_TLS13;

                EXPECT_SUCCESS(s2n_stuffer_write_bytes(&conn->in, user_canceled_alert, sizeof(user_canceled_alert)));

                EXPECT_SUCCESS(s2n_process_alert_fragment(conn));
                EXPECT_FALSE(conn->closed);

                EXPECT_SUCCESS(s2n_connection_free(conn));
                EXPECT_SUCCESS(s2n_config_free(config));
            }
        }
    }

    /* Test s2n_queue_writer_close_alert_warning */
    {
        /* Safety check */
        EXPECT_FAILURE_WITH_ERRNO(s2n_queue_writer_close_alert_warning(NULL), S2N_ERR_NULL);

        /* Does not send alert if alerts not supported */
        {
            struct s2n_config *config;
            EXPECT_NOT_NULL(config = s2n_config_new());

            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));
            EXPECT_SUCCESS(s2n_connection_set_config(conn, config));

            EXPECT_EQUAL(s2n_stuffer_data_available(&conn->writer_alert_out), 0);

            /* Writes alert by default */
            EXPECT_SUCCESS(s2n_queue_writer_close_alert_warning(conn));
            EXPECT_EQUAL(s2n_stuffer_data_available(&conn->writer_alert_out), ALERT_LEN);

            /* Wipe error */
            EXPECT_SUCCESS(s2n_stuffer_wipe(&conn->writer_alert_out));

            /* Does not write alert when alerts not supported (when QUIC mode enabled) */
            EXPECT_SUCCESS(s2n_config_enable_quic(config));
            EXPECT_SUCCESS(s2n_queue_writer_close_alert_warning(conn));
            EXPECT_EQUAL(s2n_stuffer_data_available(&conn->writer_alert_out), 0);

            EXPECT_SUCCESS(s2n_connection_free(conn));
            EXPECT_SUCCESS(s2n_config_free(config));
        }
    }

    /* Test s2n_queue_reader_alert
     *      Since s2n_queue_reader_alert is static, we'll test it indirectly via s2n_queue_reader_handshake_failure_alert */
    {
        /* Safety check */
        EXPECT_FAILURE_WITH_ERRNO(s2n_queue_reader_handshake_failure_alert(NULL), S2N_ERR_NULL);

        /* Does not send alert if alerts not supported */
        {
            struct s2n_config *config;
            EXPECT_NOT_NULL(config = s2n_config_new());

            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));
            EXPECT_SUCCESS(s2n_connection_set_config(conn, config));

            EXPECT_EQUAL(s2n_stuffer_data_available(&conn->reader_alert_out), 0);

            /* Writes alert by default */
            EXPECT_SUCCESS(s2n_queue_reader_handshake_failure_alert(conn));
            EXPECT_EQUAL(s2n_stuffer_data_available(&conn->reader_alert_out), ALERT_LEN);

            /* Wipe error */
            EXPECT_SUCCESS(s2n_stuffer_wipe(&conn->reader_alert_out));

            /* Does not write alert when alerts not supported (when QUIC mode enabled) */
            EXPECT_SUCCESS(s2n_config_enable_quic(config));
            EXPECT_SUCCESS(s2n_queue_reader_handshake_failure_alert(conn));
            EXPECT_EQUAL(s2n_stuffer_data_available(&conn->reader_alert_out), 0);

            EXPECT_SUCCESS(s2n_connection_free(conn));
            EXPECT_SUCCESS(s2n_config_free(config));
        }
    }

    END_TEST();
}
