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
#include "tls/s2n_tls.h"

static const uint8_t hello_request_msg[] = {
    /* message header */
    TLS_HELLO_REQUEST, /* msg_type = hello_request */
    0, 0, 0,           /* length = 0 */
    /* empty message body */
};

static S2N_RESULT s2n_test_send_and_recv(struct s2n_connection *send_conn, struct s2n_connection *recv_conn)
{
    RESULT_ENSURE_REF(send_conn);
    RESULT_ENSURE_REF(recv_conn);

    s2n_blocked_status blocked = S2N_NOT_BLOCKED;

    const uint8_t send_data[] = "hello world";
    ssize_t send_size = s2n_send(send_conn, send_data, sizeof(send_data), &blocked);
    RESULT_GUARD_POSIX(send_size);
    RESULT_ENSURE_EQ(send_size, sizeof(send_data));

    uint8_t recv_data[sizeof(send_data)] = { 0 };
    ssize_t recv_size = s2n_recv(recv_conn, recv_data, send_size, &blocked);
    RESULT_GUARD_POSIX(recv_size);
    RESULT_ENSURE_EQ(recv_size, send_size);
    EXPECT_BYTEARRAY_EQUAL(recv_data, send_data, send_size);

    return S2N_RESULT_OK;
}

static S2N_RESULT s2n_send_client_hello_request(struct s2n_connection *server_conn)
{
    RESULT_ENSURE_REF(server_conn);

    DEFER_CLEANUP(struct s2n_blob message_blob = { 0 }, s2n_free);
    RESULT_GUARD_POSIX(s2n_realloc(&message_blob, sizeof(hello_request_msg)));
    RESULT_CHECKED_MEMCPY(message_blob.data, hello_request_msg, message_blob.size);

    /* Send */
    s2n_blocked_status blocked = S2N_NOT_BLOCKED;
    RESULT_GUARD(s2n_record_write(server_conn, TLS_HANDSHAKE, &message_blob));
    RESULT_GUARD_POSIX(s2n_flush(server_conn, &blocked));

    /* Cleanup */
    RESULT_GUARD_POSIX(s2n_stuffer_wipe(&server_conn->out));
    RESULT_GUARD_POSIX(s2n_stuffer_wipe(&server_conn->handshake.io));

    return S2N_RESULT_OK;
}

struct s2n_test_reneg_req_ctx {
    s2n_renegotiate_response app_decision;
    uint8_t call_count;
};

static int s2n_test_reneg_req_cb(struct s2n_connection *conn, void *context, s2n_renegotiate_response *response)
{
    POSIX_ENSURE_REF(context);
    POSIX_ENSURE_REF(response);

    struct s2n_test_reneg_req_ctx *test_context = (struct s2n_test_reneg_req_ctx *) context;
    *response = test_context->app_decision;
    POSIX_ENSURE_LT(test_context->call_count, UINT8_MAX);
    test_context->call_count++;

    return S2N_SUCCESS;
}

int main(int argc, char **argv)
{
    BEGIN_TEST();

    static struct s2n_cert_chain_and_key *chain_and_key = NULL;
    EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&chain_and_key,
            S2N_DEFAULT_TEST_CERT_CHAIN, S2N_DEFAULT_TEST_PRIVATE_KEY));

    DEFER_CLEANUP(struct s2n_cert_chain_and_key *ecdsa_chain_and_key = NULL, s2n_cert_chain_and_key_ptr_free);
    EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&ecdsa_chain_and_key,
            S2N_DEFAULT_ECDSA_TEST_CERT_CHAIN, S2N_DEFAULT_ECDSA_TEST_PRIVATE_KEY));

    DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
    EXPECT_NOT_NULL(config);
    EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, "default"));
    EXPECT_SUCCESS(s2n_config_set_unsafe_for_testing(config));
    EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, chain_and_key));

    DEFER_CLEANUP(struct s2n_config *config_with_reneg_cb = s2n_config_new(), s2n_config_ptr_free);
    EXPECT_NOT_NULL(config_with_reneg_cb);
    EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config_with_reneg_cb, "default"));
    EXPECT_SUCCESS(s2n_config_set_unsafe_for_testing(config_with_reneg_cb));
    EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config_with_reneg_cb, chain_and_key));
    EXPECT_SUCCESS(s2n_config_set_renegotiate_request_cb(config_with_reneg_cb, s2n_test_reneg_req_cb, NULL));

    /* Test: Hello requests received during the handshake are a no-op */
    {
        DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(client_conn);
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config));

        DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(server_conn);
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));

        DEFER_CLEANUP(struct s2n_test_io_pair io_pair = { 0 }, s2n_io_pair_close);
        EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
        EXPECT_SUCCESS(s2n_connection_set_io_pair(client_conn, &io_pair));
        EXPECT_SUCCESS(s2n_connection_set_io_pair(server_conn, &io_pair));

        /* Start the handshake.
         * We should be able to receive the hello request in the middle of the handshake. */
        EXPECT_OK(s2n_negotiate_test_server_and_client_until_message(server_conn, client_conn,
                SERVER_HELLO_DONE));
        EXPECT_EQUAL(server_conn->server, server_conn->initial);

        /* Send a hello request */
        EXPECT_OK(s2n_send_client_hello_request(server_conn));

        /* Successfully complete the handshake */
        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));
    };

    /* Test: Hello requests received during the handshake are an error for TLS1.3 */
    if (s2n_is_tls13_fully_supported()) {
        DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(client_conn);
        EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(client_conn, "default_tls13"));
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config));

        DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(server_conn);
        EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(server_conn, "default_tls13"));
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));

        DEFER_CLEANUP(struct s2n_test_io_pair io_pair = { 0 }, s2n_io_pair_close);
        EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
        EXPECT_SUCCESS(s2n_connection_set_io_pair(client_conn, &io_pair));
        EXPECT_SUCCESS(s2n_connection_set_io_pair(server_conn, &io_pair));

        /* Start the handshake */
        EXPECT_OK(s2n_negotiate_test_server_and_client_until_message(server_conn, client_conn,
                SERVER_HELLO));

        /* Send a hello request.
         * We should be able to receive the hello request before the version is negotiated. */
        EXPECT_OK(s2n_send_client_hello_request(server_conn));

        /* Continue the handshake */
        EXPECT_OK(s2n_negotiate_test_server_and_client_until_message(server_conn, client_conn,
                ENCRYPTED_EXTENSIONS));

        /* Send a hello request.
         * We should NOT be able to receive the hello request after TLS1.3 is negotiated */
        EXPECT_EQUAL(server_conn->actual_protocol_version, S2N_TLS13);
        EXPECT_EQUAL(client_conn->actual_protocol_version, S2N_TLS13);
        EXPECT_OK(s2n_send_client_hello_request(server_conn));

        /* Handshake should fail because the HelloRequest is unexpected in TLS1.3 */
        EXPECT_FAILURE_WITH_ERRNO(s2n_negotiate_test_server_and_client(server_conn, client_conn),
                S2N_ERR_BAD_MESSAGE);
    }

    /* Test: Hello requests received after the handshake can be ignored.
     *
     * We can continue sending and receiving data after the request.
     * s2n-tls treats warnings as fatals by default though, so we must disable that behavior.
     */
    {
        DEFER_CLEANUP(struct s2n_config *config_with_warns = s2n_config_new(), s2n_config_ptr_free);
        EXPECT_NOT_NULL(config_with_warns);
        EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config_with_warns, "default"));
        EXPECT_SUCCESS(s2n_config_set_unsafe_for_testing(config_with_warns));
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config_with_warns, chain_and_key));
        EXPECT_SUCCESS(s2n_config_set_alert_behavior(config_with_warns, S2N_ALERT_IGNORE_WARNINGS));

        DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(client_conn);
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config_with_warns));

        DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(server_conn);
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config_with_warns));

        DEFER_CLEANUP(struct s2n_test_io_pair io_pair = { 0 }, s2n_io_pair_close);
        EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
        EXPECT_SUCCESS(s2n_connection_set_io_pair(client_conn, &io_pair));
        EXPECT_SUCCESS(s2n_connection_set_io_pair(server_conn, &io_pair));

        /* Complete the handshake */
        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));
        EXPECT_TRUE(client_conn->secure_renegotiation);

        /* Send some data */
        EXPECT_OK(s2n_test_send_and_recv(server_conn, client_conn));
        EXPECT_OK(s2n_test_send_and_recv(client_conn, server_conn));

        /* Send the hello request message. */
        EXPECT_OK(s2n_send_client_hello_request(server_conn));

        /* Send some more data */
        for (size_t i = 0; i < 10; i++) {
            EXPECT_OK(s2n_test_send_and_recv(server_conn, client_conn));
            EXPECT_OK(s2n_test_send_and_recv(client_conn, server_conn));
            EXPECT_TRUE(s2n_connection_check_io_status(client_conn, S2N_IO_FULL_DUPLEX));
        }
    };

    /* Test: Hello requests received after the handshake do NOT trigger a no_renegotiation alert
     * if renegotiation callbacks not set.
     *
     *= https://tools.ietf.org/rfc/rfc5246#section-7.4.1.1
     *= type=test
     *# This message MAY be ignored by
     *# the client if it does not wish to renegotiate a session, or the
     *# client may, if it wishes, respond with a no_renegotiation alert.
     **/
    {
        DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(client_conn);
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config));
        EXPECT_NULL(client_conn->config->renegotiate_request_cb);

        DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(server_conn);
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));

        DEFER_CLEANUP(struct s2n_test_io_pair io_pair = { 0 }, s2n_io_pair_close);
        EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
        EXPECT_SUCCESS(s2n_connection_set_io_pair(client_conn, &io_pair));
        EXPECT_SUCCESS(s2n_connection_set_io_pair(server_conn, &io_pair));

        /* Complete the handshake */
        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));
        EXPECT_TRUE(client_conn->secure_renegotiation);

        /* Send the hello request message. */
        EXPECT_OK(s2n_send_client_hello_request(server_conn));

        /* no_renegotation alert NOT sent and received */
        EXPECT_OK(s2n_test_send_and_recv(server_conn, client_conn));
        EXPECT_OK(s2n_test_send_and_recv(client_conn, server_conn));

        /* Callback was not set */
        EXPECT_NULL(client_conn->config->renegotiate_request_cb);
    }

    /* Test: Hello requests received after the handshake trigger a no_renegotiation alert
     * if the application rejects the renegotiation request
     *
     *= https://tools.ietf.org/rfc/rfc5746#5
     *= type=test
     *# TLS implementations SHOULD provide a mechanism to disable and enable
     *# renegotiation.
     *
     *= https://tools.ietf.org/rfc/rfc5246#section-7.4.1.1
     *= type=test
     *# This message MAY be ignored by
     *# the client if it does not wish to renegotiate a session, or the
     *# client may, if it wishes, respond with a no_renegotiation alert.
     **/
    {
        struct s2n_test_reneg_req_ctx ctx = { .app_decision = S2N_RENEGOTIATE_REJECT };

        DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(client_conn);
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config_with_reneg_cb));
        EXPECT_SUCCESS(s2n_config_set_renegotiate_request_cb(config_with_reneg_cb, s2n_test_reneg_req_cb, &ctx));

        DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(server_conn);
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));

        DEFER_CLEANUP(struct s2n_test_io_pair io_pair = { 0 }, s2n_io_pair_close);
        EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
        EXPECT_SUCCESS(s2n_connection_set_io_pair(client_conn, &io_pair));
        EXPECT_SUCCESS(s2n_connection_set_io_pair(server_conn, &io_pair));

        /* Complete the handshake */
        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));
        EXPECT_TRUE(client_conn->secure_renegotiation);

        /* Send the hello request message. */
        EXPECT_OK(s2n_send_client_hello_request(server_conn));

        /* no_renegotation alert sent and received */
        EXPECT_OK(s2n_test_send_and_recv(server_conn, client_conn));
        EXPECT_ERROR_WITH_ERRNO(s2n_test_send_and_recv(client_conn, server_conn), S2N_ERR_ALERT);
        EXPECT_EQUAL(s2n_connection_get_alert(server_conn), S2N_TLS_ALERT_NO_RENEGOTIATION);

        /* Callback triggered */
        EXPECT_NOT_NULL(client_conn->config->renegotiate_request_cb);
        EXPECT_EQUAL(ctx.call_count, 1);
    };

    /* Test: Hello requests received after the handshake do not trigger a no_renegotiation alert
     * if the application accepts the renegotiation request
     *
     *= https://tools.ietf.org/rfc/rfc5746#5
     *= type=test
     *# TLS implementations SHOULD provide a mechanism to disable and enable
     *# renegotiation.
     */
    {
        struct s2n_test_reneg_req_ctx ctx = { .app_decision = S2N_RENEGOTIATE_ACCEPT };

        DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(client_conn);
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config_with_reneg_cb));
        EXPECT_SUCCESS(s2n_config_set_renegotiate_request_cb(config_with_reneg_cb, s2n_test_reneg_req_cb, &ctx));

        DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(server_conn);
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));

        DEFER_CLEANUP(struct s2n_test_io_pair io_pair = { 0 }, s2n_io_pair_close);
        EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
        EXPECT_SUCCESS(s2n_connection_set_io_pair(client_conn, &io_pair));
        EXPECT_SUCCESS(s2n_connection_set_io_pair(server_conn, &io_pair));

        /* Complete the handshake */
        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));
        EXPECT_TRUE(client_conn->secure_renegotiation);

        /* Send the hello request message. */
        EXPECT_OK(s2n_send_client_hello_request(server_conn));

        /* no_renegotation alert NOT sent and received */
        EXPECT_OK(s2n_test_send_and_recv(server_conn, client_conn));
        EXPECT_OK(s2n_test_send_and_recv(client_conn, server_conn));

        /* Callback triggered */
        EXPECT_NOT_NULL(client_conn->config->renegotiate_request_cb);
        EXPECT_EQUAL(ctx.call_count, 1);
    }

    /* Test: Hello requests received after the handshake do not trigger a no_renegotiation alert
     * if the application ignores the renegotiation request
     */
    {
        struct s2n_test_reneg_req_ctx ctx = { .app_decision = S2N_RENEGOTIATE_IGNORE };

        DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(client_conn);
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config_with_reneg_cb));
        EXPECT_SUCCESS(s2n_config_set_renegotiate_request_cb(config_with_reneg_cb, s2n_test_reneg_req_cb, &ctx));

        DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(server_conn);
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));

        DEFER_CLEANUP(struct s2n_test_io_pair io_pair = { 0 }, s2n_io_pair_close);
        EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
        EXPECT_SUCCESS(s2n_connection_set_io_pair(client_conn, &io_pair));
        EXPECT_SUCCESS(s2n_connection_set_io_pair(server_conn, &io_pair));

        /* Complete the handshake */
        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));
        EXPECT_TRUE(client_conn->secure_renegotiation);

        /* Send the hello request message. */
        EXPECT_OK(s2n_send_client_hello_request(server_conn));

        /* no_renegotation alert NOT sent and received */
        EXPECT_OK(s2n_test_send_and_recv(server_conn, client_conn));
        EXPECT_OK(s2n_test_send_and_recv(client_conn, server_conn));

        /* Callback triggered */
        EXPECT_NOT_NULL(client_conn->config->renegotiate_request_cb);
        EXPECT_EQUAL(ctx.call_count, 1);
    }

    /* Test: Hello requests received after the handshake trigger a no_renegotiation alert
     * if secure renegotiation is not supported, even if the application would have accepted the request.
     *
     *= https://tools.ietf.org/rfc/rfc5746#section-4.2
     *= type=test
     *# This text applies if the connection's "secure_renegotiation" flag is
     *# set to FALSE.
     *#
     *# It is possible that un-upgraded servers will request that the client
     *# renegotiate.  It is RECOMMENDED that clients refuse this
     *# renegotiation request.  Clients that do so MUST respond to such
     *# requests with a "no_renegotiation" alert (RFC 5246 requires this
     *# alert to be at the "warning" level).  It is possible that the
     *# apparently un-upgraded server is in fact an attacker who is then
     *# allowing the client to renegotiate with a different, legitimate,
     *# upgraded server.
     **/
    {
        struct s2n_test_reneg_req_ctx ctx = { .app_decision = S2N_RENEGOTIATE_ACCEPT };

        DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(client_conn);
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config_with_reneg_cb));
        EXPECT_SUCCESS(s2n_config_set_renegotiate_request_cb(config_with_reneg_cb, s2n_test_reneg_req_cb, &ctx));

        DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(server_conn);
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));

        DEFER_CLEANUP(struct s2n_test_io_pair io_pair = { 0 }, s2n_io_pair_close);
        EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
        EXPECT_SUCCESS(s2n_connection_set_io_pair(client_conn, &io_pair));
        EXPECT_SUCCESS(s2n_connection_set_io_pair(server_conn, &io_pair));

        /* Complete the handshake */
        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));

        /* Force secure_renegotiation to be false */
        client_conn->secure_renegotiation = false;

        /* Send the hello request message. */
        EXPECT_OK(s2n_send_client_hello_request(server_conn));

        /* no_renegotation alert sent and received */
        EXPECT_OK(s2n_test_send_and_recv(server_conn, client_conn));
        EXPECT_ERROR_WITH_ERRNO(s2n_test_send_and_recv(client_conn, server_conn), S2N_ERR_ALERT);
        EXPECT_EQUAL(s2n_connection_get_alert(server_conn), S2N_TLS_ALERT_NO_RENEGOTIATION);

        /* Callback was not triggered */
        EXPECT_NOT_NULL(client_conn->config->renegotiate_request_cb);
        EXPECT_EQUAL(ctx.call_count, 0);
    }

    /* Test: Application callback method fails */
    {
        struct s2n_test_reneg_req_ctx ctx = { .app_decision = S2N_RENEGOTIATE_ACCEPT };

        DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(client_conn);
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config_with_reneg_cb));
        EXPECT_SUCCESS(s2n_config_set_renegotiate_request_cb(config_with_reneg_cb, s2n_test_reneg_req_cb, &ctx));

        DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(server_conn);
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));

        DEFER_CLEANUP(struct s2n_test_io_pair io_pair = { 0 }, s2n_io_pair_close);
        EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
        EXPECT_SUCCESS(s2n_connection_set_io_pair(client_conn, &io_pair));
        EXPECT_SUCCESS(s2n_connection_set_io_pair(server_conn, &io_pair));

        /* Complete the handshake */
        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));

        /* Send the hello request message. */
        EXPECT_OK(s2n_send_client_hello_request(server_conn));

        /* Force the callback to fail.
         * We're only allowed to call it UINT8_MAX times, so calling
         * one more time will cause it to fail with S2N_ERR_SAFETY.
         */
        EXPECT_NOT_NULL(client_conn->config->renegotiate_request_cb);
        ctx.call_count = UINT8_MAX;

        /* s2n_recv should not surface the callback error as S2N_ERR_SAFETY.
         * Applications won't be able to set s2n_errno to a meaningful value,
         * so we need to set it to S2N_ERR_CANCELED for them.
         */
        EXPECT_ERROR_WITH_ERRNO(s2n_test_send_and_recv(server_conn, client_conn), S2N_ERR_CANCELLED);
    };

    /* Test: SSLv3 sends a fatal handshake_failure alert instead of no_renegotiate
     *
     *= https://tools.ietf.org/rfc/rfc5746#4.5
     *= type=test
     *# SSLv3 does not define the "no_renegotiation" alert (and does
     *# not offer a way to indicate a refusal to renegotiate at a "warning"
     *# level).  SSLv3 clients that refuse renegotiation SHOULD use a fatal
     *# handshake_failure alert.
     **/
    if (s2n_hash_is_available(S2N_HASH_MD5)) {
        struct s2n_test_reneg_req_ctx ctx = { .app_decision = S2N_RENEGOTIATE_REJECT };

        DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(client_conn);
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config_with_reneg_cb));
        EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(client_conn, "test_all"));
        EXPECT_SUCCESS(s2n_config_set_renegotiate_request_cb(config_with_reneg_cb, s2n_test_reneg_req_cb, &ctx));
        EXPECT_SUCCESS(s2n_connection_set_blinding(client_conn, S2N_SELF_SERVICE_BLINDING));

        DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(server_conn);
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));
        EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(server_conn, "test_all"));

        DEFER_CLEANUP(struct s2n_test_io_pair io_pair = { 0 }, s2n_io_pair_close);
        EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
        EXPECT_SUCCESS(s2n_connections_set_io_pair(client_conn, server_conn, &io_pair));

        uint8_t buffer[1] = { 0 };
        s2n_blocked_status blocked = S2N_NOT_BLOCKED;

        /* Force an SSLv3 handshake */
        client_conn->client_protocol_version = S2N_SSLv3;
        client_conn->actual_protocol_version = S2N_SSLv3;
        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));
        EXPECT_EQUAL(client_conn->actual_protocol_version, S2N_SSLv3);
        EXPECT_EQUAL(server_conn->actual_protocol_version, S2N_SSLv3);

        /* Send the hello request message. */
        EXPECT_OK(s2n_send_client_hello_request(server_conn));

        /* handshake_failure alert queued */
        EXPECT_FAILURE_WITH_ERRNO(s2n_recv(client_conn, buffer, sizeof(buffer), &blocked), S2N_ERR_BAD_MESSAGE);
        EXPECT_TRUE(s2n_connection_check_io_status(client_conn, S2N_IO_CLOSED));

        /* handshake_failure alert send.
         * Skip blinding. */
        EXPECT_TRUE(client_conn->delay > 0);
        client_conn->delay = 0;
        EXPECT_SUCCESS(s2n_shutdown_send(client_conn, &blocked));

        /* handshake_failure alert received */
        EXPECT_FAILURE_WITH_ERRNO(s2n_recv(server_conn, buffer, sizeof(buffer), &blocked), S2N_ERR_ALERT);
        EXPECT_TRUE(s2n_connection_check_io_status(server_conn, S2N_IO_CLOSED));
        EXPECT_EQUAL(s2n_connection_get_alert(server_conn), S2N_TLS_ALERT_HANDSHAKE_FAILURE);

        /* Callback triggered */
        EXPECT_NOT_NULL(client_conn->config->renegotiate_request_cb);
        EXPECT_EQUAL(ctx.call_count, 1);
    }

    EXPECT_SUCCESS(s2n_cert_chain_and_key_free(chain_and_key));
    END_TEST();
}
