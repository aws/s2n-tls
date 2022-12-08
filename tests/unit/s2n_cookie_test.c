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

#include "tls/extensions/s2n_cookie.h"

#include <sys/param.h>

#include "s2n_test.h"
#include "testlib/s2n_testlib.h"
#include "tls/s2n_handshake_type.h"
#include "utils/s2n_random.h"
#include "utils/s2n_safety.h"

#define TEST_COOKIE_COUNT 5

int main()
{
    BEGIN_TEST();

    if (!s2n_is_tls13_fully_supported()) {
        END_TEST();
    }

    uint16_t test_cookie_sizes[TEST_COOKIE_COUNT] = { 1, UINT8_MAX, UINT8_MAX + 1, UINT16_MAX - 1, UINT16_MAX };
    struct s2n_blob test_cookies[TEST_COOKIE_COUNT] = { 0 };
    for (size_t i = 0; i < TEST_COOKIE_COUNT; i++) {
        EXPECT_SUCCESS(s2n_alloc(&test_cookies[i], test_cookie_sizes[i]));
        EXPECT_OK(s2n_get_public_random_data(&test_cookies[i]));
    }

    /**
     * Test: client only sends extension if cookie present
     *
     *= https://tools.ietf.org/rfc/rfc8446#4.1.2
     *= type=test
     *# -   Including a "cookie" extension if one was provided in the
     *#     HelloRetryRequest.
     **/
    {
        DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(client_conn);

        /* Not sent without a cookie */
        EXPECT_FALSE(s2n_client_cookie_extension.should_send(client_conn));

        /* Sent with a cookie */
        EXPECT_SUCCESS(s2n_dup(&test_cookies[0], &client_conn->cookie));
        EXPECT_TRUE(s2n_client_cookie_extension.should_send(client_conn));
    };

    /* Test: server only sends extension if cookie present
     * (cookie will never be present in production)
     */
    {
        DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(server_conn);

        /* Not sent without a cookie */
        EXPECT_FALSE(s2n_server_cookie_extension.should_send(server_conn));

        /* Sent with a cookie */
        EXPECT_SUCCESS(s2n_dup(&test_cookies[0], &server_conn->cookie));
        EXPECT_TRUE(s2n_server_cookie_extension.should_send(server_conn));
    };

    /* Test: client can parse server cookie extension */
    for (size_t i = 0; i < TEST_COOKIE_COUNT; i++) {
        DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(server_conn);

        DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(server_conn);

        DEFER_CLEANUP(struct s2n_stuffer server_extension = { 0 }, s2n_stuffer_free);
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&server_extension, 0));

        /* Server sends extension with test cookie */
        EXPECT_SUCCESS(s2n_dup(&test_cookies[i], &server_conn->cookie));
        EXPECT_SUCCESS(s2n_server_cookie_extension.send(server_conn, &server_extension));

        /* Client doesn't parse extension if no retry */
        EXPECT_FAILURE_WITH_ERRNO(s2n_server_cookie_extension.recv(client_conn, &server_extension),
                S2N_ERR_UNSUPPORTED_EXTENSION);

        /* Client parses extension if retry */
        client_conn->handshake.handshake_type = HELLO_RETRY_REQUEST;
        EXPECT_SUCCESS(s2n_server_cookie_extension.recv(client_conn, &server_extension));
        S2N_BLOB_EXPECT_EQUAL(test_cookies[i], client_conn->cookie);
    }

    /* Test: client sends correctly formatted extension */
    for (size_t i = 0; i < TEST_COOKIE_COUNT; i++) {
        DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(server_conn);

        DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(server_conn);

        DEFER_CLEANUP(struct s2n_stuffer client_extension = { 0 }, s2n_stuffer_free);
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&client_extension, 0));

        /* Client sends extension with test cookie */
        EXPECT_SUCCESS(s2n_dup(&test_cookies[i], &client_conn->cookie));
        EXPECT_SUCCESS(s2n_client_cookie_extension.send(client_conn, &client_extension));

        /* Sanity check: Server rejects incorrectly sized cookie */
        EXPECT_SUCCESS(s2n_dup(&test_cookies[i], &server_conn->cookie));
        server_conn->cookie.size--;
        EXPECT_FAILURE_WITH_ERRNO(s2n_client_cookie_extension.recv(server_conn, &client_extension),
                S2N_ERR_BAD_MESSAGE);
        EXPECT_SUCCESS(s2n_free(&server_conn->cookie));
        EXPECT_SUCCESS(s2n_stuffer_reread(&client_extension));

        /* Sanity check: Server rejects incorrect cookie data */
        EXPECT_SUCCESS(s2n_dup(&test_cookies[i], &server_conn->cookie));
        server_conn->cookie.data[0] = server_conn->cookie.data[0] + 1;
        EXPECT_FAILURE_WITH_ERRNO(s2n_client_cookie_extension.recv(server_conn, &client_extension),
                S2N_ERR_BAD_MESSAGE);
        EXPECT_SUCCESS(s2n_free(&server_conn->cookie));
        EXPECT_SUCCESS(s2n_stuffer_reread(&client_extension));

        /* Server accepts correct cookie data */
        EXPECT_SUCCESS(s2n_dup(&test_cookies[i], &server_conn->cookie));
        EXPECT_SUCCESS(s2n_client_cookie_extension.recv(server_conn, &client_extension));
    }

    DEFER_CLEANUP(struct s2n_cert_chain_and_key *chain_and_key = NULL,
            s2n_cert_chain_and_key_ptr_free);
    EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&chain_and_key,
            S2N_DEFAULT_ECDSA_TEST_CERT_CHAIN, S2N_DEFAULT_ECDSA_TEST_PRIVATE_KEY));

    DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(),
            s2n_config_ptr_free);
    EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, chain_and_key));
    EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, "default_tls13"));
    EXPECT_SUCCESS(s2n_config_disable_x509_verification(config));

    /* Although the cookie is *technically* allowed to be UINT16_MAX,
     * in reality it has to share a uint16_t extensions list length
     * with other extensions.
     *
     * So for the self-talk tests, reduce the size of any large test cookies.
     */
    for (size_t i = 0; i < TEST_COOKIE_COUNT; i++) {
        test_cookies[i].size = MIN(test_cookies[i].size, UINT16_MAX / 2);
    }

    /* Sanity check: server fails if client does not provide expected cookie */
    {
        DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(server_conn);
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));
        EXPECT_SUCCESS(s2n_connection_set_blinding(server_conn, S2N_SELF_SERVICE_BLINDING));

        DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(server_conn);
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config));

        struct s2n_test_io_pair io_pair = { 0 };
        EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
        EXPECT_SUCCESS(s2n_connections_set_io_pair(client_conn, server_conn, &io_pair));

        /* Force the HRR path */
        client_conn->security_policy_override = &security_policy_test_tls13_retry;

        /* Force the server to send a cookie */
        EXPECT_SUCCESS(s2n_dup(&test_cookies[0], &server_conn->cookie));

        /* Begin negotiating handshake.
         * The first negotiate_until blocks because the client is looking for a SERVER_HELLO,
         * not the HELLO_RETRY_MESSAGE. This is fine; it's in the right place in the handshake.
         */
        EXPECT_ERROR_WITH_ERRNO(s2n_negotiate_test_server_and_client_until_message(server_conn, client_conn, HELLO_RETRY_MSG),
                S2N_ERR_IO_BLOCKED);
        EXPECT_EQUAL(s2n_conn_get_current_message_type(server_conn), HELLO_RETRY_MSG);
        EXPECT_EQUAL(s2n_conn_get_current_message_type(client_conn), SERVER_HELLO);
        EXPECT_OK(s2n_negotiate_test_server_and_client_until_message(server_conn, client_conn, CLIENT_HELLO));
        EXPECT_EQUAL(s2n_conn_get_current_message_type(server_conn), CLIENT_HELLO);
        EXPECT_EQUAL(s2n_conn_get_current_message_type(client_conn), CLIENT_HELLO);

        /* Verify HRR path */
        EXPECT_TRUE(IS_HELLO_RETRY_HANDSHAKE(server_conn));
        EXPECT_TRUE(IS_HELLO_RETRY_HANDSHAKE(client_conn));

        /* At this point, the server has already sent its HRR request with a cookie.
         * The client has stored the server's cookie, but not responded.
         * Wipe the cookie on the client, preventing it from sending the response.
         */
        EXPECT_NOT_EQUAL(client_conn->cookie.size, 0);
        EXPECT_SUCCESS(s2n_free(&client_conn->cookie));

        /* Continue negotiating. We should fail because of the "missing" cookie. */
        EXPECT_FAILURE_WITH_ERRNO(s2n_negotiate_test_server_and_client(server_conn, client_conn),
                S2N_ERR_MISSING_EXTENSION);

        EXPECT_SUCCESS(s2n_io_pair_close(&io_pair));
    };

    /* Self-Talk: Server does NOT use cookies */
    {
        DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(server_conn);
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));

        DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(server_conn);
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config));

        struct s2n_test_io_pair io_pair = { 0 };
        EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
        EXPECT_SUCCESS(s2n_connections_set_io_pair(client_conn, server_conn, &io_pair));

        /* Force the HRR path */
        client_conn->security_policy_override = &security_policy_test_tls13_retry;

        /* Negotiate handshake */
        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));

        /* Verify HRR path */
        EXPECT_TRUE(IS_HELLO_RETRY_HANDSHAKE(server_conn));
        EXPECT_TRUE(IS_HELLO_RETRY_HANDSHAKE(client_conn));

        /* Verify no cookies */
        EXPECT_EQUAL(client_conn->cookie.size, 0);
        EXPECT_EQUAL(server_conn->cookie.size, 0);

        EXPECT_SUCCESS(s2n_shutdown_test_server_and_client(server_conn, client_conn));
        EXPECT_SUCCESS(s2n_io_pair_close(&io_pair));
    };

    /* Self-Talk: Server does use cookies
     *
     *= https://tools.ietf.org/rfc/rfc8446#section-4.2.2
     *= type=test
     *# When sending a HelloRetryRequest, the server MAY provide a "cookie"
     *# extension to the client (this is an exception to the usual rule that
     *# the only extensions that may be sent are those that appear in the
     *# ClientHello).  When sending the new ClientHello, the client MUST copy
     *# the contents of the extension received in the HelloRetryRequest into
     *# a "cookie" extension in the new ClientHello.
     */
    for (size_t i = 0; i < TEST_COOKIE_COUNT; i++) {
        DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(server_conn);
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));

        DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(server_conn);
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config));

        struct s2n_test_io_pair io_pair = { 0 };
        EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
        EXPECT_SUCCESS(s2n_connections_set_io_pair(client_conn, server_conn, &io_pair));

        /* Force the HRR path */
        client_conn->security_policy_override = &security_policy_test_tls13_retry;

        /* Force the server to send a cookie */
        EXPECT_SUCCESS(s2n_dup(&test_cookies[i], &server_conn->cookie));

        /* Negotiate handshake */
        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));

        /* Verify HRR path */
        EXPECT_TRUE(IS_HELLO_RETRY_HANDSHAKE(server_conn));
        EXPECT_TRUE(IS_HELLO_RETRY_HANDSHAKE(client_conn));

        /* Verify cookies */
        S2N_BLOB_EXPECT_EQUAL(test_cookies[i], client_conn->cookie);
        S2N_BLOB_EXPECT_EQUAL(test_cookies[i], server_conn->cookie);

        EXPECT_SUCCESS(s2n_shutdown_test_server_and_client(server_conn, client_conn));
        EXPECT_SUCCESS(s2n_io_pair_close(&io_pair));
    }

    /* Self-Talk: Full connection lifecycle with cookies
     * We try the handshake multiple times with different possible call patterns.
     */
    {
        DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(server_conn);
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));

        DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(server_conn);
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config));

        /* We need an arbitrary combination of conditions,
         * but consistent across test runs.
         */
        srand(0);

        for (size_t i = 0; i < 250; i++) {
            int r = rand();
            bool hrr = (r % 2) == 0;
            bool cookie = (r % 3) == 0;
            size_t cookie_i = i % TEST_COOKIE_COUNT;
            bool free_handshake = (r % 7) == 0;

            /* Verify calls to s2n_connection_wipe are safe */
            EXPECT_SUCCESS(s2n_connection_wipe(client_conn));
            EXPECT_SUCCESS(s2n_connection_wipe(server_conn));

            /* Create nonblocking pipes */
            struct s2n_test_io_pair io_pair = { 0 };
            EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
            EXPECT_SUCCESS(s2n_connections_set_io_pair(client_conn, server_conn, &io_pair));

            /* Force the HRR path */
            if (hrr) {
                client_conn->security_policy_override = &security_policy_test_tls13_retry;
            }

            /* Force the server to send a cookie */
            if (cookie) {
                EXPECT_SUCCESS(s2n_dup(&test_cookies[cookie_i], &server_conn->cookie));
            }

            /* Negotiate handshake */
            EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));

            /* Verify HRR path */
            if (hrr) {
                EXPECT_TRUE(s2n_is_hello_retry_handshake(server_conn));
                EXPECT_TRUE(s2n_is_hello_retry_handshake(client_conn));
            } else {
                EXPECT_FALSE(s2n_is_hello_retry_handshake(server_conn));
                EXPECT_FALSE(s2n_is_hello_retry_handshake(client_conn));
            }

            /* Verify cookie data */
            if (hrr && cookie) {
                S2N_BLOB_EXPECT_EQUAL(test_cookies[cookie_i], client_conn->cookie);
            } else {
                EXPECT_EQUAL(client_conn->cookie.size, 0);
            }

            if (free_handshake) {
                EXPECT_SUCCESS(s2n_connection_free_handshake(client_conn));
                EXPECT_SUCCESS(s2n_connection_free_handshake(server_conn));
            }

            EXPECT_SUCCESS(s2n_shutdown_test_server_and_client(server_conn, client_conn));
            EXPECT_SUCCESS(s2n_io_pair_close(&io_pair));
        }
    };

    for (size_t i = 0; i < TEST_COOKIE_COUNT; i++) {
        EXPECT_SUCCESS(s2n_free(&test_cookies[i]));
    }
    END_TEST();
}
