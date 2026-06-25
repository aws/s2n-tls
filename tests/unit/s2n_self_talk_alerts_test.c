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
#include <unistd.h>

#include "api/s2n.h"
#include "s2n_test.h"
#include "testlib/s2n_testlib.h"

#define TLS_ALERT         21
#define TLS_ALERT_VERSION 0x03, 0x03
#define TLS_ALERT_LENGTH  0x00, 0x02

#define TLS_ALERT_LEVEL_WARNING 1
#define TLS_ALERT_LEVEL_FATAL   2

#define TLS_ALERT_CLOSE_NOTIFY      0
#define TLS_ALERT_UNRECOGNIZED_NAME 122

struct alert_ctx {
    int write_fd;
    int invoked;
    int count;

    uint8_t level;
    uint8_t code;
};

int client_hello_send_alerts(struct s2n_connection *conn, void *ctx)
{
    struct alert_ctx *alert = ctx;
    uint8_t alert_msg[] = { TLS_ALERT, TLS_ALERT_VERSION, TLS_ALERT_LENGTH, alert->level, alert->code };

    for (int i = 0; i < alert->count; i++) {
        if (s2n_test_send(alert->write_fd, alert_msg, sizeof(alert_msg)) != sizeof(alert_msg)) {
            return -1;
        }

        alert->invoked++;
    }

    return 0;
}

int main(int argc, char **argv)
{
    BEGIN_TEST();

    DEFER_CLEANUP(struct s2n_cert_chain_and_key *chain_and_key = NULL, s2n_cert_chain_and_key_ptr_free);
    EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&chain_and_key,
            S2N_DEFAULT_TEST_CERT_CHAIN, S2N_DEFAULT_TEST_PRIVATE_KEY));

    /* Test that we ignore Warning Alerts in S2N_ALERT_IGNORE_WARNINGS mode in TLS1.2 */
    {
        DEFER_CLEANUP(struct s2n_config *server_config = s2n_config_new(), s2n_config_ptr_free);
        EXPECT_NOT_NULL(server_config);
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(server_config, chain_and_key));
        EXPECT_SUCCESS(s2n_config_set_cipher_preferences(server_config, "20240501"));

        DEFER_CLEANUP(struct s2n_config *client_config = s2n_config_new(), s2n_config_ptr_free);
        EXPECT_NOT_NULL(client_config);
        EXPECT_SUCCESS(s2n_config_set_cipher_preferences(client_config, "20240501"));
        EXPECT_SUCCESS(s2n_config_disable_x509_verification(client_config));
        EXPECT_SUCCESS(s2n_config_set_alert_behavior(client_config, S2N_ALERT_IGNORE_WARNINGS));

        struct s2n_test_io_pair io_pair;
        EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));

        /* Set up the callback to send warning alerts after receiving ClientHello */
        struct alert_ctx warning_alert = { .write_fd = io_pair.server, .invoked = 0, .count = 2, .level = TLS_ALERT_LEVEL_WARNING, .code = TLS_ALERT_UNRECOGNIZED_NAME };
        EXPECT_SUCCESS(s2n_config_set_client_hello_cb(server_config, client_hello_send_alerts, &warning_alert));

        DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER), s2n_connection_ptr_free);
        EXPECT_NOT_NULL(server_conn);
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, server_config));
        EXPECT_SUCCESS(s2n_connection_set_io_pair(server_conn, &io_pair));

        DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT), s2n_connection_ptr_free);
        EXPECT_NOT_NULL(client_conn);
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, client_config));
        EXPECT_SUCCESS(s2n_connection_set_io_pair(client_conn, &io_pair));

        /* Negotiate the handshake -- should succeed since warnings are ignored */
        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));
        EXPECT_EQUAL(client_conn->actual_protocol_version, S2N_TLS12);

        /* Ensure that callback was invoked */
        EXPECT_EQUAL(warning_alert.invoked, 2);

        /* Verify data transfer still works after the warning alerts were ignored.
         * Send a range of payload sizes, including sizes large enough to span
         * multiple TLS records, and verify every byte is received correctly.
         * Because the IO pair is non-blocking and both peers run in the same
         * process, interleave send and recv so a large payload that fills the
         * in-memory buffer can't deadlock. */
        s2n_blocked_status blocked = S2N_NOT_BLOCKED;
        uint8_t send_buffer[0xffff] = { 0 };
        uint8_t recv_buffer[0xffff] = { 0 };
        for (size_t size = 1; size < s2n_array_len(send_buffer); size += 100) {
            POSIX_CHECKED_MEMSET(&send_buffer[0], 33, size);

            size_t total_sent = 0;
            size_t total_received = 0;
            while (total_received < size) {
                if (total_sent < size) {
                    ssize_t sent = s2n_send(client_conn, send_buffer + total_sent,
                            size - total_sent, &blocked);
                    if (sent > 0) {
                        total_sent += sent;
                    } else {
                        EXPECT_EQUAL(s2n_error_get_type(s2n_errno), S2N_ERR_T_BLOCKED);
                    }
                }

                ssize_t received = s2n_recv(server_conn, recv_buffer + total_received,
                        size - total_received, &blocked);
                if (received > 0) {
                    total_received += received;
                } else {
                    EXPECT_EQUAL(s2n_error_get_type(s2n_errno), S2N_ERR_T_BLOCKED);
                }
            }

            EXPECT_EQUAL(total_received, size);
            for (size_t j = 0; j < size; j++) {
                EXPECT_EQUAL(recv_buffer[j], 33);
            }
        }

        EXPECT_SUCCESS(s2n_shutdown_test_server_and_client(server_conn, client_conn));
        EXPECT_SUCCESS(s2n_io_pair_close(&io_pair));
    };

    /* Test that we don't ignore Fatal Alerts in S2N_ALERT_IGNORE_WARNINGS mode in TLS1.2 */
    {
        DEFER_CLEANUP(struct s2n_config *server_config = s2n_config_new(), s2n_config_ptr_free);
        EXPECT_NOT_NULL(server_config);
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(server_config, chain_and_key));
        EXPECT_SUCCESS(s2n_config_set_cipher_preferences(server_config, "20240501"));

        DEFER_CLEANUP(struct s2n_config *client_config = s2n_config_new(), s2n_config_ptr_free);
        EXPECT_NOT_NULL(client_config);
        EXPECT_SUCCESS(s2n_config_set_cipher_preferences(client_config, "20240501"));
        EXPECT_SUCCESS(s2n_config_disable_x509_verification(client_config));
        EXPECT_SUCCESS(s2n_config_set_alert_behavior(client_config, S2N_ALERT_IGNORE_WARNINGS));

        struct s2n_test_io_pair io_pair;
        EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));

        /* Set up the callback to send a fatal alert after receiving ClientHello */
        struct alert_ctx fatal_alert = { .write_fd = io_pair.server, .invoked = 0, .count = 1, .level = TLS_ALERT_LEVEL_FATAL, .code = TLS_ALERT_UNRECOGNIZED_NAME };
        EXPECT_SUCCESS(s2n_config_set_client_hello_cb(server_config, client_hello_send_alerts, &fatal_alert));

        DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER), s2n_connection_ptr_free);
        EXPECT_NOT_NULL(server_conn);
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, server_config));
        EXPECT_SUCCESS(s2n_connection_set_io_pair(server_conn, &io_pair));

        DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT), s2n_connection_ptr_free);
        EXPECT_NOT_NULL(client_conn);
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, client_config));
        EXPECT_SUCCESS(s2n_connection_set_blinding(client_conn, S2N_SELF_SERVICE_BLINDING));
        EXPECT_SUCCESS(s2n_connection_set_io_pair(client_conn, &io_pair));

        /* Negotiate the handshake -- should fail due to fatal alert */
        EXPECT_FAILURE(s2n_negotiate_test_server_and_client(server_conn, client_conn));

        /* Ensure that callback was invoked */
        EXPECT_EQUAL(fatal_alert.invoked, 1);

        EXPECT_SUCCESS(s2n_io_pair_close(&io_pair));
    };

    /* Test that we don't ignore Warning Alerts in S2N_ALERT_FAIL_ON_WARNINGS mode in TLS1.2 */
    {
        DEFER_CLEANUP(struct s2n_config *server_config = s2n_config_new(), s2n_config_ptr_free);
        EXPECT_NOT_NULL(server_config);
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(server_config, chain_and_key));
        EXPECT_SUCCESS(s2n_config_set_cipher_preferences(server_config, "20240501"));

        DEFER_CLEANUP(struct s2n_config *client_config = s2n_config_new(), s2n_config_ptr_free);
        EXPECT_NOT_NULL(client_config);
        EXPECT_SUCCESS(s2n_config_set_cipher_preferences(client_config, "20240501"));
        EXPECT_SUCCESS(s2n_config_disable_x509_verification(client_config));
        EXPECT_SUCCESS(s2n_config_set_alert_behavior(client_config, S2N_ALERT_FAIL_ON_WARNINGS));

        struct s2n_test_io_pair io_pair;
        EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));

        /* Set up the callback to send a warning alert after receiving ClientHello */
        struct alert_ctx warning_alert = { .write_fd = io_pair.server, .invoked = 0, .count = 1, .level = TLS_ALERT_LEVEL_WARNING, .code = TLS_ALERT_UNRECOGNIZED_NAME };
        EXPECT_SUCCESS(s2n_config_set_client_hello_cb(server_config, client_hello_send_alerts, &warning_alert));

        DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER), s2n_connection_ptr_free);
        EXPECT_NOT_NULL(server_conn);
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, server_config));
        EXPECT_SUCCESS(s2n_connection_set_io_pair(server_conn, &io_pair));

        DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT), s2n_connection_ptr_free);
        EXPECT_NOT_NULL(client_conn);
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, client_config));
        EXPECT_SUCCESS(s2n_connection_set_blinding(client_conn, S2N_SELF_SERVICE_BLINDING));
        EXPECT_SUCCESS(s2n_connection_set_io_pair(client_conn, &io_pair));

        /* Negotiate the handshake -- should fail since warnings are treated as errors */
        EXPECT_FAILURE(s2n_negotiate_test_server_and_client(server_conn, client_conn));

        /* Ensure that callback was invoked */
        EXPECT_EQUAL(warning_alert.invoked, 1);

        EXPECT_SUCCESS(s2n_io_pair_close(&io_pair));
    };

    END_TEST();
}
