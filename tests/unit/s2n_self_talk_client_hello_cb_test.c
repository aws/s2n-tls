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

#include <fcntl.h>
#include <stdint.h>
#include <sys/wait.h>
#include <unistd.h>

#include "api/s2n.h"
#include "s2n_test.h"
#include "testlib/s2n_testlib.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_internal.h"

struct client_hello_context {
    int invoked;
    int swap_config_during_callback;
    int swap_config_nonblocking_mode;
    int mark_done_during_callback;
    struct s2n_config *config;
    /* the right way to mark server name extenstion was used
     * after parsing ClientHello is to call
     * s2n_connection_server_name_extension_used
     *
     * this flag tests the previous behavior from blocking callbacks
     */
    int legacy_rc_for_server_name_used;
};

int mock_client(struct s2n_test_io_pair *io_pair, int expect_failure, int expect_server_name_used)
{
    struct s2n_connection *conn;
    struct s2n_config *config;
    s2n_blocked_status blocked;
    int result = 0;
    int rc = 0;
    const char *protocols[] = { "h2", "http/1.1" };

    /* Give the server a chance to listen */
    sleep(1);

    conn = s2n_connection_new(S2N_CLIENT);
    config = s2n_config_new();
    s2n_config_set_protocol_preferences(config, protocols, 2);
    s2n_config_disable_x509_verification(config);
    s2n_connection_set_config(conn, config);

    s2n_connection_set_io_pair(conn, io_pair);

    s2n_set_server_name(conn, "example.com");

    rc = s2n_negotiate(conn, &blocked);
    if (expect_failure) {
        if (!rc) {
            result = 1;
        }

        if (s2n_connection_get_alert(conn) != 40) {
            result = 2;
        }
    } else {
        char buffer[0xffff];

        if (conn->server_name_used != expect_server_name_used) {
            result = 1;
        }

        if (rc < 0) {
            result = 2;
        }

        for (int i = 1; i < 0xffff; i += 100) {
            memset(buffer, 33, sizeof(char) * i);
            s2n_send(conn, buffer, i, &blocked);
        }

        int shutdown_rc = -1;
        do {
            shutdown_rc = s2n_shutdown(conn, &blocked);
        } while (shutdown_rc != 0);
    }

    s2n_connection_free(conn);
    s2n_config_free(config);

    /* Give the server a chance to a void a sigpipe */
    sleep(1);

    s2n_cleanup();
    s2n_io_pair_close_one_end(io_pair, S2N_CLIENT);

    exit(result);
}

int client_hello_swap_config(struct s2n_connection *conn, void *ctx)
{
    struct client_hello_context *client_hello_ctx;
    struct s2n_client_hello *client_hello = s2n_connection_get_client_hello(conn);
    const char *sent_server_name = "example.com";
    const char *received_server_name;
    if (ctx == NULL) {
        return -1;
    }
    client_hello_ctx = ctx;
    /* Increment counter to ensure that callback was invoked */
    client_hello_ctx->invoked++;

    /* Validate SNI extension */
    uint8_t expected_server_name[] = {
        /* Server names len */
        0x00, 0x0E,
        /* Server name type - host name */
        0x00,
        /* First server name len */
        0x00, 0x0B,
        /* First server name, matches sent_server_name */
        'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm'
    };

    /* Get SNI extension from client hello */
    uint32_t len = s2n_client_hello_get_extension_length(client_hello, S2N_EXTENSION_SERVER_NAME);
    if (len != 16) {
        return -1;
    }

    uint8_t ser_name[16] = { 0 };
    if (s2n_client_hello_get_extension_by_id(client_hello, S2N_EXTENSION_SERVER_NAME, ser_name, len) <= 0) {
        return -1;
    }

    /* Verify correct server name is returned. */
    received_server_name = s2n_get_server_name(conn);
    if (received_server_name == NULL || strcmp(received_server_name, sent_server_name)) {
        return -1;
    }

    if (memcmp(ser_name, expected_server_name, len) != 0) {
        return -1;
    }

    if (client_hello_ctx->mark_done_during_callback) {
        EXPECT_SUCCESS(s2n_client_hello_cb_done(conn));
    }

    if (client_hello_ctx->swap_config_during_callback) {
        EXPECT_SUCCESS(s2n_connection_set_config(conn, client_hello_ctx->config));
        if (client_hello_ctx->legacy_rc_for_server_name_used) {
            return 1;
        }
        EXPECT_SUCCESS(s2n_connection_server_name_extension_used(conn));
        return 0;
    }

    return 0;
}

int client_hello_fail_handshake(struct s2n_connection *conn, void *ctx)
{
    struct client_hello_context *client_hello_ctx;

    if (ctx == NULL) {
        return -1;
    }
    client_hello_ctx = ctx;

    /* Incremet counter to ensure that callback was invoked */
    client_hello_ctx->invoked++;

    /* Return negative value to terminate the handshake */
    return -1;
}

int s2n_negotiate_nonblocking_ch_cb(struct s2n_connection *conn,
        struct client_hello_context *ch_ctx, bool server_name_used)
{
    s2n_blocked_status blocked;
    EXPECT_NOT_NULL(conn);
    /* negotiate handshake, we should pause after the nonblocking callback is invoked */
    EXPECT_FAILURE_WITH_ERRNO(s2n_negotiate(conn, &blocked), S2N_ERR_ASYNC_BLOCKED);
    EXPECT_EQUAL(blocked, S2N_BLOCKED_ON_APPLICATION_INPUT);

    /* verify client hello cb has been invoked */
    EXPECT_EQUAL(ch_ctx->invoked, 1);

    /* while handshake is paused, swap the config if asked */
    if (ch_ctx->swap_config_nonblocking_mode) {
        EXPECT_SUCCESS(s2n_connection_set_config(conn, ch_ctx->config));
    }
    /* unless explicitly unblocked we should stay paused */
    EXPECT_FAILURE_WITH_ERRNO(s2n_negotiate(conn, &blocked), S2N_ERR_ASYNC_BLOCKED);
    EXPECT_EQUAL(blocked, S2N_BLOCKED_ON_APPLICATION_INPUT);

    /* mark the client hello cb complete */
    EXPECT_SUCCESS(s2n_client_hello_cb_done(conn));
    if (server_name_used) {
        EXPECT_SUCCESS(s2n_connection_server_name_extension_used(conn));
    }
    return s2n_negotiate(conn, &blocked);
}

int s2n_negotiate_blocking_ch_cb(struct s2n_connection *conn, struct client_hello_context *ch_ctx)
{
    s2n_blocked_status blocked;
    EXPECT_NOT_NULL(conn);

    int rc = s2n_negotiate(conn, &blocked);
    /* verify client hello cb has been invoked */
    EXPECT_EQUAL(ch_ctx->invoked, 1);
    return rc;
}

int server_recv(struct s2n_connection *conn)
{
    static char buffer[0xffff];
    s2n_blocked_status blocked;

    for (int i = 1; i < 0xffff; i += 100) {
        char *ptr = buffer;
        int size = i;

        do {
            int bytes_read = 0;
            EXPECT_SUCCESS(bytes_read = s2n_recv(conn, ptr, size, &blocked));

            size -= bytes_read;
            ptr += bytes_read;
        } while (size);

        for (int j = 0; j < i; j++) {
            EXPECT_EQUAL((buffer)[j], 33);
        }
    }
    return S2N_SUCCESS;
}

int init_server_conn(struct s2n_connection **conn, struct s2n_test_io_pair *io_pair,
        struct s2n_config *config)
{
    /* This is the server process, close the client end of the pipe */
    EXPECT_SUCCESS(s2n_io_pair_close_one_end(io_pair, S2N_CLIENT));

    EXPECT_NOT_NULL(*conn = s2n_connection_new(S2N_SERVER));

    /* Set up the connection to read from the fd */
    EXPECT_SUCCESS(s2n_connection_set_io_pair(*conn, io_pair));
    EXPECT_SUCCESS(s2n_connection_set_config(*conn, config));
    return S2N_SUCCESS;
}

int start_client_conn(struct s2n_test_io_pair *io_pair, pid_t *pid,
        int expect_failure, int expect_server_name_used)
{
    /* Create a pipe */
    EXPECT_SUCCESS(s2n_io_pair_init(io_pair));

    /* Create a child process */
    *pid = fork();
    if (*pid == 0) {
        /* This is the client process, close the server end of the pipe */
        EXPECT_SUCCESS(s2n_io_pair_close_one_end(io_pair, S2N_SERVER));

        mock_client(io_pair, expect_failure, expect_server_name_used);
    }
    return S2N_SUCCESS;
}

static int test_case_clean(struct s2n_connection *conn, pid_t client_pid,
        struct s2n_config *config, struct s2n_test_io_pair *io_pair,
        struct client_hello_context *ch_ctx, struct s2n_cert_chain_and_key *chain_and_key)
{
    s2n_blocked_status blocked;
    int status;

    EXPECT_SUCCESS(s2n_shutdown(conn, &blocked));
    EXPECT_EQUAL(waitpid(-1, &status, 0), client_pid);
    EXPECT_EQUAL(status, 0);
    /* client process cleans their end, we just need to close server side */
    EXPECT_SUCCESS(s2n_io_pair_close_one_end(io_pair, S2N_SERVER));

    EXPECT_SUCCESS(s2n_connection_free(conn));
    EXPECT_SUCCESS(s2n_config_free(config));
    memset(ch_ctx, 0, sizeof(struct client_hello_context));
    EXPECT_SUCCESS(s2n_cert_chain_and_key_free(chain_and_key));

    return S2N_SUCCESS;
}

int run_test_config_swap_ch_cb(s2n_client_hello_cb_mode cb_mode,
        struct client_hello_context *ch_ctx)
{
    struct s2n_test_io_pair io_pair;
    struct s2n_config *config;
    struct s2n_connection *conn;
    struct s2n_config *swap_config;
    pid_t pid;
    struct s2n_cert_chain_and_key *chain_and_key;

    EXPECT_SUCCESS(start_client_conn(&io_pair, &pid, 0, 1));

    /* Add application protocols to swapped config */
    static const char *protocols[] = { "h2" };
    EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&chain_and_key, S2N_DEFAULT_TEST_CERT_CHAIN, S2N_DEFAULT_TEST_PRIVATE_KEY));

    /* prepare swap_config */
    EXPECT_NOT_NULL(swap_config = s2n_config_new());
    EXPECT_SUCCESS(s2n_config_set_protocol_preferences(swap_config, protocols, 1));
    EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(swap_config, chain_and_key));
    ch_ctx->config = swap_config;
    /* in the swap config make sure blocking more is SET correctly */
    EXPECT_SUCCESS(s2n_config_set_client_hello_cb_mode(swap_config, cb_mode));

    /* Don't set up certificate and private key for the main config, so if
     * handshake succeeds we know that config was swapped */
    EXPECT_NOT_NULL(config = s2n_config_new());

    /* Set up the callback */
    EXPECT_SUCCESS(s2n_config_set_client_hello_cb_mode(config, cb_mode));
    EXPECT_SUCCESS(s2n_config_set_client_hello_cb(config, client_hello_swap_config, ch_ctx));

    EXPECT_SUCCESS(init_server_conn(&conn, &io_pair, config));

    /* do the handshake */
    if (cb_mode == S2N_CLIENT_HELLO_CB_NONBLOCKING && !ch_ctx->mark_done_during_callback) {
        /* swap the config and mark server_name_used in the async context */
        EXPECT_SUCCESS(s2n_negotiate_nonblocking_ch_cb(conn, ch_ctx, true));
    } else {
        /* cb_mode == S2N_CLIENT_HELLO_CB_BLOCKING or NONBLOCKING mode where
         * a non blocking callback marks cb_done during the callback itself
         */
        EXPECT_SUCCESS(s2n_negotiate_blocking_ch_cb(conn, ch_ctx));
    }

    /* Server name and error are as expected with null connection */
    EXPECT_NULL(s2n_get_server_name(NULL));
    EXPECT_EQUAL(s2n_errno, S2N_ERR_NULL);

    /* Expect most preferred negotiated protocol which only swap_config had */
    EXPECT_STRING_EQUAL(s2n_get_application_protocol(conn), protocols[0]);

    EXPECT_SUCCESS(server_recv(conn));

    EXPECT_SUCCESS(test_case_clean(conn, pid, config, &io_pair, ch_ctx, chain_and_key));
    EXPECT_SUCCESS(s2n_config_free(swap_config));
    return S2N_SUCCESS;
}

int run_test_no_config_swap_ch_cb(s2n_client_hello_cb_mode cb_mode, struct client_hello_context *ch_ctx)
{
    struct s2n_test_io_pair io_pair;
    struct s2n_config *config;
    struct s2n_connection *conn;
    pid_t pid;
    struct s2n_cert_chain_and_key *chain_and_key;

    EXPECT_SUCCESS(start_client_conn(&io_pair, &pid, 0, 0));

    EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&chain_and_key, S2N_DEFAULT_TEST_CERT_CHAIN, S2N_DEFAULT_TEST_PRIVATE_KEY));
    EXPECT_NOT_NULL(config = s2n_config_new());
    EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, chain_and_key));

    /* Setup ClientHello callback */
    EXPECT_SUCCESS(s2n_config_set_client_hello_cb(config, client_hello_swap_config, ch_ctx));
    EXPECT_SUCCESS(s2n_config_set_client_hello_cb_mode(config, cb_mode));
    EXPECT_SUCCESS(init_server_conn(&conn, &io_pair, config));

    /* do the handshake */
    if (cb_mode == S2N_CLIENT_HELLO_CB_NONBLOCKING) {
        /* swap the config and mark server_name_used in the async context */
        EXPECT_SUCCESS(s2n_negotiate_nonblocking_ch_cb(conn, ch_ctx, false));
    } else { /* cb_mode == S2N_CLIENT_HELLO_CB_BLOCKING */
        EXPECT_SUCCESS(s2n_negotiate_blocking_ch_cb(conn, ch_ctx));
    }

    /* Server name and error are as expected with null connection */
    EXPECT_NULL(s2n_get_server_name(NULL));
    EXPECT_EQUAL(s2n_errno, S2N_ERR_NULL);

    EXPECT_SUCCESS(server_recv(conn));

    EXPECT_SUCCESS(test_case_clean(conn, pid, config, &io_pair, ch_ctx, chain_and_key));
    return S2N_SUCCESS;
}

int run_test_reject_handshake_ch_cb(s2n_client_hello_cb_mode cb_mode, struct client_hello_context *ch_ctx)
{
    struct s2n_test_io_pair io_pair;
    struct s2n_config *config;
    struct s2n_connection *conn;
    pid_t pid;
    s2n_blocked_status blocked;
    struct s2n_cert_chain_and_key *chain_and_key;

    EXPECT_SUCCESS(start_client_conn(&io_pair, &pid, 1, 0));

    EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&chain_and_key, S2N_DEFAULT_TEST_CERT_CHAIN, S2N_DEFAULT_TEST_PRIVATE_KEY));
    EXPECT_NOT_NULL(config = s2n_config_new());
    EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, chain_and_key));

    /* Setup ClientHello callback */
    EXPECT_SUCCESS(s2n_config_set_client_hello_cb(config, client_hello_fail_handshake, ch_ctx));
    EXPECT_SUCCESS(s2n_config_set_client_hello_cb_mode(config, cb_mode));

    EXPECT_SUCCESS(init_server_conn(&conn, &io_pair, config));
    /* If s2n_negotiate fails, it usually would delay with a sleep. In order to
     * test that we don't blind when CLientHello callback fails the handshake,
     * disable blinding here */
    EXPECT_SUCCESS(s2n_connection_set_blinding(conn, S2N_SELF_SERVICE_BLINDING));

    /* Negotiate the handshake. */
    EXPECT_FAILURE_WITH_ERRNO(s2n_negotiate(conn, &blocked), S2N_ERR_CANCELLED);

    /* Check that blinding was not invoked */
    EXPECT_EQUAL(s2n_connection_get_delay(conn), 0);

    /* Ensure that callback was invoked */
    EXPECT_EQUAL(ch_ctx->invoked, 1);

    /* shutdown to flush alert */
    EXPECT_SUCCESS(test_case_clean(conn, pid, config, &io_pair, ch_ctx, chain_and_key));
    return S2N_SUCCESS;
}

int main(int argc, char **argv)
{
    struct client_hello_context client_hello_ctx = { 0 };
    BEGIN_TEST();
    /* Test config swapping in client hello callback */

    /* we want to update the config outside of callback so don't swap in callback */
    client_hello_ctx.swap_config_nonblocking_mode = 1;
    EXPECT_SUCCESS(run_test_config_swap_ch_cb(S2N_CLIENT_HELLO_CB_NONBLOCKING, &client_hello_ctx));

    /* non blocking callback when callback marks cb_done during the callback */
    client_hello_ctx.swap_config_during_callback = 1;
    client_hello_ctx.mark_done_during_callback = 1;
    EXPECT_SUCCESS(run_test_config_swap_ch_cb(S2N_CLIENT_HELLO_CB_NONBLOCKING, &client_hello_ctx));

    /* we want to update the config in the callback */
    client_hello_ctx.swap_config_during_callback = 1;
    EXPECT_SUCCESS(run_test_config_swap_ch_cb(S2N_CLIENT_HELLO_CB_BLOCKING, &client_hello_ctx));

    /* validate legacy behavior for server_name_used */
    /* we want to update the config in the callback */
    client_hello_ctx.swap_config_during_callback = 1;
    client_hello_ctx.legacy_rc_for_server_name_used = 1;
    EXPECT_SUCCESS(run_test_config_swap_ch_cb(S2N_CLIENT_HELLO_CB_BLOCKING, &client_hello_ctx));

    /* Tests for test when server_name_used is not set */
    EXPECT_SUCCESS(run_test_no_config_swap_ch_cb(S2N_CLIENT_HELLO_CB_BLOCKING, &client_hello_ctx));

    EXPECT_SUCCESS(run_test_no_config_swap_ch_cb(S2N_CLIENT_HELLO_CB_NONBLOCKING, &client_hello_ctx));

    /* Test rejecting connection in client hello callback */
    EXPECT_SUCCESS(run_test_reject_handshake_ch_cb(S2N_CLIENT_HELLO_CB_BLOCKING, &client_hello_ctx));

    EXPECT_SUCCESS(run_test_reject_handshake_ch_cb(S2N_CLIENT_HELLO_CB_NONBLOCKING, &client_hello_ctx));

    END_TEST();

    return 0;
}
