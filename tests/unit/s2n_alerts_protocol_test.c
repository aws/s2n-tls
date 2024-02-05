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
#include "tls/s2n_alerts.h"
#include "tls/s2n_tls.h"

#define ERROR_ALERTS_COUNT (UINT16_MAX)
#define END_OF_DATA        0
#define MODE_COUNT         2

int s2n_test_ch_cb(struct s2n_connection *conn, void *context)
{
    return S2N_FAILURE;
}

typedef enum {
    S2N_TEST_DURING_HANDSHAKE,
    S2N_TEST_AFTER_HANDSHAKE,
    S2N_TEST_TYPE_COUNT
} s2n_test_type;

int main(int argc, char **argv)
{
    BEGIN_TEST();

    if (!s2n_is_tls13_fully_supported()) {
        return 0;
    }

    uint8_t alert_header[] = {
        /* type */
        TLS_ALERT,
        /* legacy_record_version */
        0x03, 0x03,
        /* length */
        0x00, 0x02
    };
    uint8_t close_notify[] = { 1, S2N_TLS_ALERT_CLOSE_NOTIFY };
    uint8_t data[] = "hello";

    /**
     *= https://tools.ietf.org/rfc/rfc8446#section-6
     *= type=test
     *# Unknown Alert types MUST be treated as error alerts.
     */
    uint8_t test_alert_levels[] = { 0, 1, 2, 3, 10, UINT8_MAX };

    /**
     *= https://tools.ietf.org/rfc/rfc8446#section-6
     *= type=test
     *# All the alerts listed in Section 6.2 MUST be sent with
     *# AlertLevel=fatal and MUST be treated as error alerts when received
     *# regardless of the AlertLevel in the message.
     */
    uint8_t error_alerts[ERROR_ALERTS_COUNT][2] = { 0 };
    size_t error_alerts_count = 0;
    for (size_t level_i = 0; level_i < s2n_array_len(test_alert_levels); level_i++) {
        for (size_t alert_code = 0; alert_code <= UINT8_MAX; alert_code++) {
            /* Skip closure alerts */
            if (alert_code == S2N_TLS_ALERT_CLOSE_NOTIFY) {
                continue;
            }
            if (alert_code == S2N_TLS_ALERT_USER_CANCELED) {
                continue;
            }

            /* To speed up the test, let's exclude a chunk of the unassigned values. */
            if (alert_code > 120 && alert_code < 250) {
                continue;
            }

            EXPECT_TRUE(error_alerts_count < ERROR_ALERTS_COUNT);
            error_alerts[error_alerts_count][0] = test_alert_levels[level_i];
            error_alerts[error_alerts_count][1] = alert_code;
            error_alerts_count++;
        }
    }

    DEFER_CLEANUP(struct s2n_cert_chain_and_key *chain_and_key = NULL,
            s2n_cert_chain_and_key_ptr_free);
    EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&chain_and_key,
            S2N_DEFAULT_TEST_CERT_CHAIN, S2N_DEFAULT_TEST_PRIVATE_KEY));

    DEFER_CLEANUP(struct s2n_cert_chain_and_key *ecdsa_chain_and_key = NULL,
            s2n_cert_chain_and_key_ptr_free);
    EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&ecdsa_chain_and_key,
            S2N_DEFAULT_ECDSA_TEST_CERT_CHAIN, S2N_DEFAULT_ECDSA_TEST_PRIVATE_KEY));

    DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(),
            s2n_config_ptr_free);
    EXPECT_SUCCESS(s2n_config_set_unsafe_for_testing(config));
    EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, "default_tls13"));
    EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, chain_and_key));

    DEFER_CLEANUP(struct s2n_config *ecdsa_config = s2n_config_new(),
            s2n_config_ptr_free);
    EXPECT_SUCCESS(s2n_config_set_unsafe_for_testing(ecdsa_config));
    EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(ecdsa_config, ecdsa_chain_and_key));

    /* Test: Receiving an error alert */
    for (size_t i = 0; i < error_alerts_count; i++) {
        for (s2n_test_type type = 0; type < S2N_TEST_TYPE_COUNT; type++) {
            for (uint8_t mode = 0; mode < MODE_COUNT; mode++) {
                DEFER_CLEANUP(struct s2n_connection *server = s2n_connection_new(S2N_SERVER),
                        s2n_connection_ptr_free);
                EXPECT_SUCCESS(s2n_connection_set_blinding(server, S2N_SELF_SERVICE_BLINDING));
                EXPECT_SUCCESS(s2n_connection_set_config(server, config));

                DEFER_CLEANUP(struct s2n_connection *client = s2n_connection_new(S2N_CLIENT),
                        s2n_connection_ptr_free);
                EXPECT_SUCCESS(s2n_connection_set_blinding(client, S2N_SELF_SERVICE_BLINDING));
                EXPECT_SUCCESS(s2n_connection_set_config(client, config));

                DEFER_CLEANUP(struct s2n_test_io_stuffer_pair io_pair = { 0 }, s2n_io_stuffer_pair_free);
                EXPECT_OK(s2n_io_stuffer_pair_init(&io_pair));
                EXPECT_OK(s2n_connections_set_io_stuffer_pair(client, server, &io_pair));

                if (type == S2N_TEST_DURING_HANDSHAKE) {
                    /* Partially perform handshake */
                    EXPECT_OK(s2n_negotiate_test_server_and_client_until_message(server, client, SERVER_CERT));
                } else {
                    /* Complete handshake */
                    EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server, client));
                }
                EXPECT_EQUAL(server->actual_protocol_version, S2N_TLS13);

                struct s2n_connection *receiver = server;
                struct s2n_connection *sender = client;
                if (mode == S2N_CLIENT) {
                    receiver = client;
                    sender = server;
                }

                /* Send alert */
                struct s2n_blob alert = { 0 };
                s2n_blocked_status blocked = S2N_NOT_BLOCKED;
                EXPECT_SUCCESS(s2n_blob_init(&alert, error_alerts[i], sizeof(error_alerts[0])));
                EXPECT_OK(s2n_record_write(sender, TLS_ALERT, &alert));
                EXPECT_SUCCESS(s2n_flush(sender, &blocked));

                /**
                 *= https://tools.ietf.org/rfc/rfc8446#section-6
                 *= type=test
                 *# Upon receiving an error alert, the TLS implementation
                 *# SHOULD indicate an error to the application and MUST NOT allow any
                 *# further data to be sent or received on the connection.
                 */
                if (type == S2N_TEST_DURING_HANDSHAKE) {
                    EXPECT_FAILURE_WITH_ERRNO(s2n_negotiate(receiver, &blocked), S2N_ERR_ALERT);
                    EXPECT_FAILURE_WITH_ERRNO(s2n_negotiate(receiver, &blocked), S2N_ERR_CLOSED);
                } else {
                    EXPECT_FAILURE_WITH_ERRNO(s2n_recv(receiver, data, sizeof(data), &blocked), S2N_ERR_ALERT);
                    EXPECT_FAILURE_WITH_ERRNO(s2n_recv(receiver, data, sizeof(data), &blocked), S2N_ERR_CLOSED);
                    EXPECT_FAILURE_WITH_ERRNO(s2n_send(receiver, data, sizeof(data), &blocked), S2N_ERR_CLOSED);
                }

                /**
                 *= https://tools.ietf.org/rfc/rfc8446#section-6.2
                 *= type=test
                 *# Upon transmission or
                 *# receipt of a fatal alert message, both parties MUST immediately close
                 *# the connection.
                 */
                EXPECT_TRUE(s2n_connection_check_io_status(receiver, S2N_IO_CLOSED));

                /**
                 *= https://tools.ietf.org/rfc/rfc8446#section-6.2
                 *= type=test
                 *# The implementation SHOULD provide a way to facilitate logging the sending
                 *# and receiving of alerts.
                 */
                EXPECT_EQUAL(error_alerts[i][1], s2n_connection_get_alert(receiver));
            }
        }
    };

    /* Test: Sending an error alert */
    {
        /* Testing a variety of alerts is more difficult sending than receiving.
         * We can't trigger every possible fatal error, so just choose some common ones.
         */
        int test_errors[] = {
            /* handshake errors without blinding */
            S2N_ERR_CANCELLED,
            S2N_ERR_CIPHER_NOT_SUPPORTED,
            /* handshake errors with blinding */
            S2N_ERR_PROTOCOL_DOWNGRADE_DETECTED,
            S2N_ERR_CERT_UNTRUSTED,
            /* application data error */
            S2N_ERR_DECRYPT,
        };

        DEFER_CLEANUP(struct s2n_config *bad_cb_config = s2n_config_new(),
                s2n_config_ptr_free);
        EXPECT_SUCCESS(s2n_config_set_client_hello_cb(bad_cb_config, s2n_test_ch_cb, NULL));

        DEFER_CLEANUP(struct s2n_config *untrusted_config = s2n_config_new(),
                s2n_config_ptr_free);

        for (size_t i = 0; i < s2n_array_len(test_errors); i++) {
            DEFER_CLEANUP(struct s2n_connection *server = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            EXPECT_SUCCESS(s2n_connection_set_blinding(server, S2N_SELF_SERVICE_BLINDING));
            EXPECT_SUCCESS(s2n_connection_set_config(server, config));

            DEFER_CLEANUP(struct s2n_connection *client = s2n_connection_new(S2N_CLIENT),
                    s2n_connection_ptr_free);
            EXPECT_SUCCESS(s2n_connection_set_blinding(client, S2N_SELF_SERVICE_BLINDING));
            EXPECT_SUCCESS(s2n_connection_set_config(client, config));

            DEFER_CLEANUP(struct s2n_test_io_stuffer_pair io_pair = { 0 }, s2n_io_stuffer_pair_free);
            EXPECT_OK(s2n_io_stuffer_pair_init(&io_pair));
            EXPECT_OK(s2n_connections_set_io_stuffer_pair(client, server, &io_pair));

            s2n_blocked_status blocked = S2N_NOT_BLOCKED;
            uint8_t expected_alert = S2N_TLS_ALERT_CLOSE_NOTIFY;
            struct s2n_connection *failed_conn = server;
            struct s2n_connection *closed_conn = client;

            switch (test_errors[i]) {
                case S2N_ERR_CANCELLED:
                    /* Error triggered by callback failure during handshake */
                    EXPECT_SUCCESS(s2n_connection_set_config(server, bad_cb_config));
                    EXPECT_FAILURE_WITH_ERRNO(s2n_negotiate_test_server_and_client(server, client),
                            S2N_ERR_CANCELLED);

                    expected_alert = S2N_TLS_ALERT_HANDSHAKE_FAILURE;
                    break;
                case S2N_ERR_CIPHER_NOT_SUPPORTED:
                    /* Error triggered if no valid cipher suites.
                     * Use a security policy that only supports RSA certs for the client,
                     * and only set an EC cert for the server.
                     */
                    EXPECT_SUCCESS(s2n_connection_set_config(server, ecdsa_config));
                    EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(client, "20170210"));

                    EXPECT_FAILURE_WITH_ERRNO(s2n_negotiate_test_server_and_client(server, client),
                            S2N_ERR_CIPHER_NOT_SUPPORTED);
                    break;
                case S2N_ERR_PROTOCOL_DOWNGRADE_DETECTED:
                    /* Remove TLS1.3 support before the ClientHello by setting
                     * a security policy that doesn't support TLS1.3, then add
                     * TLS1.3 support back after the ClientHello.
                     */
                    EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(client, "20170210"));
                    EXPECT_FAILURE_WITH_ERRNO(s2n_negotiate(client, &blocked), S2N_ERR_IO_BLOCKED);
                    EXPECT_FAILURE_WITH_ERRNO(s2n_negotiate(server, &blocked), S2N_ERR_IO_BLOCKED);
                    client->client_protocol_version = S2N_TLS13;

                    EXPECT_FAILURE_WITH_ERRNO(s2n_negotiate_test_server_and_client(server, client),
                            S2N_ERR_PROTOCOL_DOWNGRADE_DETECTED);

                    failed_conn = client;
                    closed_conn = server;
                    break;
                case S2N_ERR_CERT_UNTRUSTED:
                    EXPECT_SUCCESS(s2n_connection_set_config(client, untrusted_config));

                    EXPECT_FAILURE_WITH_ERRNO(s2n_negotiate_test_server_and_client(server, client),
                            S2N_ERR_CERT_UNTRUSTED);

                    failed_conn = client;
                    closed_conn = server;
                    break;
                case S2N_ERR_DECRYPT:
                    EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server, client));

                    /* The server will expect the original sequence number,
                     * not our updated sequence number, so fail to decrypt.
                     */
                    client->secure->client_sequence_number[0] = 0xFF;
                    EXPECT_EQUAL(s2n_send(client, data, sizeof(data), &blocked), sizeof(data));
                    EXPECT_FAILURE_WITH_ERRNO(s2n_recv(server, data, sizeof(data), &blocked),
                            S2N_ERR_DECRYPT);
                    break;
                default:
                    FAIL_MSG("Fatal error not implemented for test");
            }

            /* Remove any blinding so that we can immediately call shutdown */
            failed_conn->delay = 0;

            /* The alert will not be sent until we attempt to shutdown */
            EXPECT_SUCCESS(s2n_shutdown_send(failed_conn, &blocked));
            EXPECT_TRUE(failed_conn->alert_sent);

            /**
             *= https://tools.ietf.org/rfc/rfc8446#section-6.2
             *= type=test
             *# Upon transmission or
             *# receipt of a fatal alert message, both parties MUST immediately close
             *# the connection.
             */
            EXPECT_TRUE(s2n_connection_check_io_status(failed_conn, S2N_IO_CLOSED));

            /**
             *= https://tools.ietf.org/rfc/rfc8446#section-6.2
             *= type=test
             *# Whenever an implementation encounters a fatal error condition, it
             *# SHOULD send an appropriate fatal alert
             */
            if (expected_alert == S2N_TLS_ALERT_CLOSE_NOTIFY) {
                EXPECT_EQUAL(s2n_recv(closed_conn, data, sizeof(data), &blocked), END_OF_DATA);
                EXPECT_EQUAL(blocked, S2N_NOT_BLOCKED);
            } else {
                EXPECT_FAILURE_WITH_ERRNO(s2n_recv(closed_conn, data, sizeof(data), &blocked), S2N_ERR_ALERT);
            }
            EXPECT_EQUAL(expected_alert, s2n_connection_get_alert(closed_conn));
            /**
             *= https://tools.ietf.org/rfc/rfc8446#section-6.2
             *= type=test
             *# and MUST close the connection
             *# without sending or receiving any additional data.
             */
            EXPECT_FAILURE_WITH_ERRNO(s2n_send(failed_conn, data, sizeof(data), &blocked),
                    S2N_ERR_CLOSED);
            EXPECT_FAILURE_WITH_ERRNO(s2n_recv(failed_conn, data, sizeof(data), &blocked), S2N_ERR_CLOSED);
        }
    };

    /* Test: Receiving a closure alert
     *
     *= https://tools.ietf.org/rfc/rfc8446#section-6.1
     *= type=test
     *# Either party MAY initiate a close of its write side of the connection
     *# by sending a "close_notify" alert.  Any data received after a closure
     *# alert has been received MUST be ignored.
     */
    for (s2n_test_type type = 0; type < S2N_TEST_TYPE_COUNT; type++) {
        for (uint8_t mode = 0; mode < MODE_COUNT; mode++) {
            DEFER_CLEANUP(struct s2n_connection *server = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            EXPECT_SUCCESS(s2n_connection_set_blinding(server, S2N_SELF_SERVICE_BLINDING));
            EXPECT_SUCCESS(s2n_connection_set_config(server, config));

            DEFER_CLEANUP(struct s2n_connection *client = s2n_connection_new(S2N_CLIENT),
                    s2n_connection_ptr_free);
            EXPECT_SUCCESS(s2n_connection_set_blinding(client, S2N_SELF_SERVICE_BLINDING));
            EXPECT_SUCCESS(s2n_connection_set_config(client, config));

            DEFER_CLEANUP(struct s2n_test_io_stuffer_pair io_pair = { 0 }, s2n_io_stuffer_pair_free);
            EXPECT_OK(s2n_io_stuffer_pair_init(&io_pair));
            EXPECT_OK(s2n_connections_set_io_stuffer_pair(client, server, &io_pair));

            if (type == S2N_TEST_DURING_HANDSHAKE) {
                /* Partially perform handshake */
                EXPECT_OK(s2n_negotiate_test_server_and_client_until_message(server, client, SERVER_CERT));
            } else {
                /* Complete handshake */
                EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server, client));
            }

            struct s2n_connection *receiver = server;
            struct s2n_stuffer *input = &io_pair.server_in;
            if (mode == S2N_CLIENT) {
                receiver = client;
                input = &io_pair.client_in;
            }

            /* Send close_notify */
            EXPECT_SUCCESS(s2n_stuffer_write_bytes(input, alert_header, sizeof(alert_header)));
            EXPECT_SUCCESS(s2n_stuffer_write_bytes(input, close_notify, sizeof(close_notify)));

            /* Receive close_notify */
            s2n_blocked_status blocked = S2N_NOT_BLOCKED;
            if (type == S2N_TEST_DURING_HANDSHAKE) {
                EXPECT_FAILURE_WITH_ERRNO(s2n_negotiate(receiver, &blocked), S2N_ERR_CLOSED);
            } else {
                EXPECT_EQUAL(s2n_recv(receiver, data, sizeof(data), &blocked), END_OF_DATA);
                EXPECT_EQUAL(blocked, S2N_NOT_BLOCKED);
            }
            EXPECT_FALSE(s2n_connection_check_io_status(receiver, S2N_IO_READABLE));

            /*
             *= https://tools.ietf.org/rfc/rfc8446#section-6.1
             *= type=test
             *# Any data received after a closure alert has been received MUST be ignored.
             */
            EXPECT_SUCCESS(s2n_stuffer_write_bytes(input, data, sizeof(data)));
            if (type == S2N_TEST_DURING_HANDSHAKE) {
                EXPECT_FAILURE_WITH_ERRNO(s2n_negotiate(receiver, &blocked), S2N_ERR_CLOSED);
            } else {
                EXPECT_EQUAL(s2n_recv(receiver, data, sizeof(data), &blocked), END_OF_DATA);
                EXPECT_EQUAL(blocked, S2N_NOT_BLOCKED);
            }
        };
    };

    /* Test: Sending a closure alert
     *
     *= https://tools.ietf.org/rfc/rfc8446#section-6.1
     *= type=test
     *# Each party MUST send a "close_notify" alert before closing its write
     *# side of the connection, unless it has already sent some error alert.
     *# This does not have any effect on its read side of the connection.
     */
    for (uint8_t mode = 0; mode < MODE_COUNT; mode++) {
        DEFER_CLEANUP(struct s2n_connection *server = s2n_connection_new(S2N_SERVER),
                s2n_connection_ptr_free);
        EXPECT_SUCCESS(s2n_connection_set_blinding(server, S2N_SELF_SERVICE_BLINDING));
        EXPECT_SUCCESS(s2n_connection_set_config(server, config));

        DEFER_CLEANUP(struct s2n_connection *client = s2n_connection_new(S2N_CLIENT),
                s2n_connection_ptr_free);
        EXPECT_SUCCESS(s2n_connection_set_blinding(client, S2N_SELF_SERVICE_BLINDING));
        EXPECT_SUCCESS(s2n_connection_set_config(client, config));

        DEFER_CLEANUP(struct s2n_test_io_stuffer_pair io_pair = { 0 }, s2n_io_stuffer_pair_free);
        EXPECT_OK(s2n_io_stuffer_pair_init(&io_pair));
        EXPECT_OK(s2n_connections_set_io_stuffer_pair(client, server, &io_pair));

        /* Perform handshake */
        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server, client));
        EXPECT_EQUAL(server->actual_protocol_version, S2N_TLS13);

        struct s2n_connection *sender = server;
        struct s2n_connection *receiver = client;
        if (mode == S2N_CLIENT) {
            sender = client;
            receiver = server;
        }

        /* Send close_notify */
        s2n_blocked_status blocked = S2N_NOT_BLOCKED;
        EXPECT_SUCCESS(s2n_shutdown_send(sender, &blocked));
        EXPECT_FALSE(s2n_connection_check_io_status(sender, S2N_IO_WRITABLE));

        /* Receive close_notify
         *
         *= https://tools.ietf.org/rfc/rfc8446#section-6
         *= type=test
         *# The "close_notify" alert is used to indicate orderly closure of one
         *# direction of the connection.  Upon receiving such an alert, the TLS
         *# implementation SHOULD indicate end-of-data to the application.
         */
        EXPECT_EQUAL(s2n_recv(receiver, data, sizeof(data), &blocked), END_OF_DATA);
        EXPECT_FALSE(s2n_connection_check_io_status(receiver, S2N_IO_READABLE));
        EXPECT_EQUAL(blocked, S2N_NOT_BLOCKED);

        /* Read side is NOT affected.
         * The receiver of the close_notify can continue to send, and the sender
         * should continue to read.
         */
        EXPECT_EQUAL(s2n_send(receiver, data, sizeof(data), &blocked), sizeof(data));
        EXPECT_EQUAL(blocked, S2N_NOT_BLOCKED);
        EXPECT_EQUAL(s2n_recv(sender, data, sizeof(data), &blocked), sizeof(data));
        EXPECT_EQUAL(blocked, S2N_NOT_BLOCKED);

        /* Respond with close_notify */
        EXPECT_SUCCESS(s2n_shutdown(receiver, &blocked));
        EXPECT_SUCCESS(s2n_shutdown(sender, &blocked));
    };

    /* Test: Closure alerts in TLS1.2
     *
     *= https://tools.ietf.org/rfc/rfc8446#section-6.1
     *= type=test
     *# Note that this is a change from versions of TLS prior to TLS 1.3 in
     *# which implementations were required to react to a "close_notify" by
     *# discarding pending writes and sending an immediate "close_notify"
     *# alert of their own.
     */
    for (uint8_t mode = 0; mode < MODE_COUNT; mode++) {
        DEFER_CLEANUP(struct s2n_connection *server = s2n_connection_new(S2N_SERVER),
                s2n_connection_ptr_free);
        EXPECT_SUCCESS(s2n_connection_set_blinding(server, S2N_SELF_SERVICE_BLINDING));
        EXPECT_SUCCESS(s2n_connection_set_config(server, config));
        EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(server, "default"));

        DEFER_CLEANUP(struct s2n_connection *client = s2n_connection_new(S2N_CLIENT),
                s2n_connection_ptr_free);
        EXPECT_SUCCESS(s2n_connection_set_blinding(client, S2N_SELF_SERVICE_BLINDING));
        EXPECT_SUCCESS(s2n_connection_set_config(client, config));
        EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(client, "default"));

        DEFER_CLEANUP(struct s2n_test_io_stuffer_pair io_pair = { 0 }, s2n_io_stuffer_pair_free);
        EXPECT_OK(s2n_io_stuffer_pair_init(&io_pair));
        EXPECT_OK(s2n_connections_set_io_stuffer_pair(client, server, &io_pair));

        /* Perform handshake */
        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server, client));
        EXPECT_EQUAL(server->actual_protocol_version, S2N_TLS12);

        struct s2n_connection *sender = server;
        struct s2n_connection *receiver = client;
        if (mode == S2N_CLIENT) {
            sender = client;
            receiver = server;
        }

        /* Send close_notify */
        s2n_blocked_status blocked = S2N_NOT_BLOCKED;
        EXPECT_SUCCESS(s2n_shutdown_send(sender, &blocked));
        EXPECT_TRUE(s2n_connection_check_io_status(sender, S2N_IO_CLOSED));

        /* Receive close_notify */
        EXPECT_EQUAL(s2n_recv(receiver, data, sizeof(data), &blocked), END_OF_DATA);
        EXPECT_TRUE(s2n_connection_check_io_status(receiver, S2N_IO_CLOSED));
        EXPECT_EQUAL(blocked, S2N_NOT_BLOCKED);

        /* Read side is affected.
         * The receiver should discard writes and just send a close_notify.
         */
        EXPECT_FAILURE_WITH_ERRNO(s2n_send(receiver, data, sizeof(data), &blocked),
                S2N_ERR_CLOSED);

        /* Respond with close_notify */
        EXPECT_SUCCESS(s2n_shutdown(receiver, &blocked));
        EXPECT_SUCCESS(s2n_shutdown(sender, &blocked));
    };

    /* Test: End-of-Data
     *
     *= https://tools.ietf.org/rfc/rfc8446#6.1
     *= type=test
     *# If a transport-level close
     *# is received prior to a "close_notify", the receiver cannot know that
     *# all the data that was sent has been received.
     *
     *= https://tools.ietf.org/rfc/rfc8446#6.1
     *= type=test
     *# If the application protocol using TLS provides that any data may be
     *# carried over the underlying transport after the TLS connection is
     *# closed, the TLS implementation MUST receive a "close_notify" alert
     *# before indicating end-of-data to the application layer.
     */
    for (uint8_t mode = 0; mode < MODE_COUNT; mode++) {
        /* Test: Without partial read */
        {
            DEFER_CLEANUP(struct s2n_connection *server = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            EXPECT_SUCCESS(s2n_connection_set_blinding(server, S2N_SELF_SERVICE_BLINDING));
            EXPECT_SUCCESS(s2n_connection_set_config(server, config));

            DEFER_CLEANUP(struct s2n_connection *client = s2n_connection_new(S2N_CLIENT),
                    s2n_connection_ptr_free);
            EXPECT_SUCCESS(s2n_connection_set_blinding(client, S2N_SELF_SERVICE_BLINDING));
            EXPECT_SUCCESS(s2n_connection_set_config(client, config));

            DEFER_CLEANUP(struct s2n_test_io_pair io_pair = { 0 }, s2n_io_pair_close);
            EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
            EXPECT_SUCCESS(s2n_connections_set_io_pair(client, server, &io_pair));

            /* Perform handshake */
            EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server, client));

            /* Close one end of pipe */
            EXPECT_SUCCESS(s2n_io_pair_close_one_end(&io_pair, mode));

            struct s2n_connection *receiver = client;
            if (mode == S2N_CLIENT) {
                receiver = server;
            }

            /* Subsequent reads should NOT report END_OF_DATA, but instead an error */
            s2n_blocked_status blocked = S2N_NOT_BLOCKED;
            for (size_t i = 0; i < 5; i++) {
                EXPECT_FAILURE_WITH_ERRNO(s2n_recv(receiver, data, sizeof(data), &blocked),
                        S2N_ERR_CLOSED);
                EXPECT_FALSE(s2n_connection_check_io_status(receiver, S2N_IO_READABLE));
            }
        };

        /* Test: With partial read */
        {
            /* In order to trigger a partial read, we need to encounter end-of-data
             * when some data has already been successfully read. For that to be true,
             * we need to read multiple records (one successfully, then end-of-data).
             */
            struct s2n_config partial_write_config_copy = *config;
            partial_write_config_copy.recv_multi_record = true;

            DEFER_CLEANUP(struct s2n_connection *server = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            EXPECT_SUCCESS(s2n_connection_set_blinding(server, S2N_SELF_SERVICE_BLINDING));
            EXPECT_SUCCESS(s2n_connection_set_config(server, &partial_write_config_copy));

            DEFER_CLEANUP(struct s2n_connection *client = s2n_connection_new(S2N_CLIENT),
                    s2n_connection_ptr_free);
            EXPECT_SUCCESS(s2n_connection_set_blinding(client, S2N_SELF_SERVICE_BLINDING));
            EXPECT_SUCCESS(s2n_connection_set_config(client, &partial_write_config_copy));

            DEFER_CLEANUP(struct s2n_test_io_pair io_pair = { 0 }, s2n_io_pair_close);
            EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
            EXPECT_SUCCESS(s2n_connections_set_io_pair(client, server, &io_pair));

            /* Perform handshake */
            EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server, client));

            struct s2n_connection *sender = server;
            struct s2n_connection *receiver = client;
            if (mode == S2N_CLIENT) {
                sender = client;
                receiver = server;
            }

            /* Send some data */
            const uint8_t partial_write = sizeof(data) / 2;
            s2n_blocked_status blocked = S2N_NOT_BLOCKED;
            EXPECT_EQUAL(s2n_send(sender, data, partial_write, &blocked), partial_write);
            EXPECT_EQUAL(blocked, S2N_NOT_BLOCKED);

            /* Close one end of pipe */
            EXPECT_SUCCESS(s2n_io_pair_close_one_end(&io_pair, mode));

            /* First read should report a partial read, but also close the connection */
            EXPECT_EQUAL(s2n_recv(receiver, data, sizeof(data), &blocked), partial_write);
            EXPECT_FALSE(s2n_connection_check_io_status(receiver, S2N_IO_READABLE));

            /* Since we read at least one byte, the blocked status should be S2N_NOT_BLOCKED */
            EXPECT_EQUAL(blocked, S2N_NOT_BLOCKED);

            /* Subsequent reads should NOT report END_OF_DATA, but instead an error */
            for (size_t i = 0; i < 5; i++) {
                EXPECT_FAILURE_WITH_ERRNO(s2n_recv(receiver, data, sizeof(data), &blocked),
                        S2N_ERR_CLOSED);
            }
        };
    };

    END_TEST();
}
