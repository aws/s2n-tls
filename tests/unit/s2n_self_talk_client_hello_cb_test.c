/*
 * Copyright 2017 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

#include <sys/wait.h>
#include <unistd.h>
#include <stdint.h>
#include <fcntl.h>

#include <s2n.h>
#include <tls/s2n_connection.h>

struct client_hello_context {
    int invoked;
    int swap_config;
    struct s2n_config *config;
};

int mock_client(int writefd, int readfd, int expect_failure, int expect_server_name_used)
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

    s2n_connection_set_read_fd(conn, readfd);
    s2n_connection_set_write_fd(conn, writefd);

    s2n_set_server_name(conn, "example.com");

    rc = s2n_negotiate(conn, &blocked);
    if (expect_failure) {
        if (!rc) {
            result = 1;
        }

        if (s2n_connection_get_alert(conn) != 40){
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

        int shutdown_rc= -1;
        do {
            shutdown_rc = s2n_shutdown(conn, &blocked);
        } while(shutdown_rc != 0);
    }

    s2n_connection_free(conn);
    s2n_config_free(config);

    /* Give the server a chance to a void a sigpipe */
    sleep(1);

    s2n_cleanup();

    _exit(result);
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
            'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm'};

    /* Get SNI extension from client hello */
    uint32_t len = s2n_client_hello_get_extension_length(client_hello, S2N_EXTENSION_SERVER_NAME);
    if (len != 16) {
        return -1;
    }

    uint8_t ser_name[16] = {0};
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

    if (client_hello_ctx->swap_config) {
        s2n_connection_set_config(conn, client_hello_ctx->config);
        return 1;
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

int main(int argc, char **argv)
{
    char buffer[0xffff];
    struct s2n_connection *conn;
    struct s2n_config *config;
    struct s2n_config *swap_config;
    s2n_blocked_status blocked;
    int status;
    pid_t pid;
    int server_to_client[2];
    int client_to_server[2];
    struct client_hello_context client_hello_ctx;
    char *cert_chain_pem;
    char *private_key_pem;
    struct s2n_cert_chain_and_key *chain_and_key;

    BEGIN_TEST();

    /* Test config swapping in client hello callback */
    EXPECT_NOT_NULL(config = s2n_config_new());
    /* Don't set up certificate and private key for the main config, so if
     * handshake succeeds we know that config was swapped */

    /* Create a new config used, which will swap the current one */
    EXPECT_NOT_NULL(swap_config = s2n_config_new());

    EXPECT_NOT_NULL(cert_chain_pem = malloc(S2N_MAX_TEST_PEM_SIZE));
    EXPECT_NOT_NULL(private_key_pem = malloc(S2N_MAX_TEST_PEM_SIZE));
    EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_CERT_CHAIN, cert_chain_pem, S2N_MAX_TEST_PEM_SIZE));
    EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_PRIVATE_KEY, private_key_pem, S2N_MAX_TEST_PEM_SIZE));
    EXPECT_NOT_NULL(chain_and_key = s2n_cert_chain_and_key_new());
    EXPECT_SUCCESS(s2n_cert_chain_and_key_load_pem(chain_and_key, cert_chain_pem, private_key_pem));
    EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(swap_config, chain_and_key));

    /* Add application protocols to swapped config */
    const char *protocols[] = { "h2" };
    EXPECT_SUCCESS(s2n_config_set_protocol_preferences(swap_config, protocols, 1));

    /* Prepare context */
    client_hello_ctx.invoked = 0;
    client_hello_ctx.swap_config = 1;
    client_hello_ctx.config = swap_config;

    /* Set up the callback to swap config on client hello */
    EXPECT_SUCCESS(s2n_config_set_client_hello_cb(config, client_hello_swap_config, &client_hello_ctx));

    /* Create a pipe */
    EXPECT_SUCCESS(pipe(server_to_client));
    EXPECT_SUCCESS(pipe(client_to_server));

    /* Create a child process */
    pid = fork();
    if (pid == 0) {
        /* This is the child process, close the read end of the pipe */
        EXPECT_SUCCESS(close(client_to_server[0]));
        EXPECT_SUCCESS(close(server_to_client[1]));

        mock_client(client_to_server[1], server_to_client[0], 0, 1);
    }

    /* This is the parent */
    EXPECT_SUCCESS(close(client_to_server[1]));
    EXPECT_SUCCESS(close(server_to_client[0]));

    EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
    EXPECT_SUCCESS(s2n_connection_set_config(conn, config));

    /* Set up the connection to read from the fd */
    EXPECT_SUCCESS(s2n_connection_set_read_fd(conn, client_to_server[0]));
    EXPECT_SUCCESS(s2n_connection_set_write_fd(conn, server_to_client[1]));

    /* Negotiate the handshake. */
    EXPECT_SUCCESS(s2n_negotiate(conn, &blocked));

    /* Server name and error are as expected with null connection */
    EXPECT_NULL(s2n_get_server_name(NULL));
    EXPECT_EQUAL(s2n_errno, S2N_ERR_NULL);

    /* Ensure that callback was invoked */
    EXPECT_EQUAL(client_hello_ctx.invoked, 1);

    /* Expect most preferred negotiated protocol */
    EXPECT_STRING_EQUAL(s2n_get_application_protocol(conn), protocols[0]);

    for (int i = 1; i < 0xffff; i += 100) {
        char * ptr = buffer;
        int size = i;

        do {
            int bytes_read = 0;
            EXPECT_SUCCESS(bytes_read = s2n_recv(conn, ptr, size, &blocked));

            size -= bytes_read;
            ptr += bytes_read;
        } while(size);

        for (int j = 0; j < i; j++) {
            EXPECT_EQUAL(buffer[j], 33);
        }
    }

    EXPECT_SUCCESS(s2n_shutdown(conn, &blocked));
    EXPECT_SUCCESS(s2n_connection_free(conn));

    /* Clean up */
    EXPECT_EQUAL(waitpid(-1, &status, 0), pid);
    EXPECT_EQUAL(status, 0);
    EXPECT_SUCCESS(s2n_config_free(config));

    /* Test no config swapping in client hello callback */
    EXPECT_NOT_NULL(config = s2n_config_new());
    EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, chain_and_key));

    /* Setup ClientHello callback */
    client_hello_ctx.invoked = 0;
    client_hello_ctx.swap_config = 0;
    client_hello_ctx.config = NULL;
    EXPECT_SUCCESS(s2n_config_set_client_hello_cb(config, client_hello_swap_config, &client_hello_ctx));

    /* Create a pipe */
    EXPECT_SUCCESS(pipe(server_to_client));
    EXPECT_SUCCESS(pipe(client_to_server));

    /* Create a child process */
    pid = fork();
    if (pid == 0) {
        /* This is the child process, close the read end of the pipe */
        EXPECT_SUCCESS(close(client_to_server[0]));
        EXPECT_SUCCESS(close(server_to_client[1]));

        mock_client(client_to_server[1], server_to_client[0], 0, 0);
    }

    /* This is the parent */
    EXPECT_SUCCESS(close(client_to_server[1]));
    EXPECT_SUCCESS(close(server_to_client[0]));

    EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
    EXPECT_SUCCESS(s2n_connection_set_config(conn, config));

    /* Set up the connection to read from the fd */
    EXPECT_SUCCESS(s2n_connection_set_read_fd(conn, client_to_server[0]));
    EXPECT_SUCCESS(s2n_connection_set_write_fd(conn, server_to_client[1]));

    /* Negotiate the handshake. */
    EXPECT_SUCCESS(s2n_negotiate(conn, &blocked));

    /* Server name and error are as expected with null connection */
    EXPECT_NULL(s2n_get_server_name(NULL));
    EXPECT_EQUAL(s2n_errno, S2N_ERR_NULL);

    /* Ensure that callback was invoked */
    EXPECT_EQUAL(client_hello_ctx.invoked, 1);

    for (int i = 1; i < 0xffff; i += 100) {
        char * ptr = buffer;
        int size = i;

        do {
            int bytes_read = 0;
            EXPECT_SUCCESS(bytes_read = s2n_recv(conn, ptr, size, &blocked));

            size -= bytes_read;
            ptr += bytes_read;
        } while(size);

        for (int j = 0; j < i; j++) {
            EXPECT_EQUAL(buffer[j], 33);
        }
    }

    EXPECT_SUCCESS(s2n_shutdown(conn, &blocked));
    EXPECT_SUCCESS(s2n_connection_free(conn));

    /* Clean up */
    EXPECT_EQUAL(waitpid(-1, &status, 0), pid);
    EXPECT_EQUAL(status, 0);
    EXPECT_SUCCESS(s2n_config_free(config));
    EXPECT_SUCCESS(s2n_config_free(swap_config));

    /* Test rejecting connection in client hello callback */
    EXPECT_NOT_NULL(config = s2n_config_new());
    EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, chain_and_key));

    /* Setup ClientHello callback */
    client_hello_ctx.invoked = 0;
    client_hello_ctx.swap_config = 0;
    client_hello_ctx.config = NULL;
    EXPECT_SUCCESS(s2n_config_set_client_hello_cb(config, client_hello_fail_handshake, &client_hello_ctx));

    /* Create a pipe */
    EXPECT_SUCCESS(pipe(server_to_client));
    EXPECT_SUCCESS(pipe(client_to_server));

    /* Create a child process */
    pid = fork();
    if (pid == 0) {
        /* This is the child process, close the read end of the pipe */
        EXPECT_SUCCESS(close(client_to_server[0]));
        EXPECT_SUCCESS(close(server_to_client[1]));

        mock_client(client_to_server[1], server_to_client[0], 1, 0);
    }

    /* This is the parent */
    EXPECT_SUCCESS(close(client_to_server[1]));
    EXPECT_SUCCESS(close(server_to_client[0]));

    EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
    EXPECT_SUCCESS(s2n_connection_set_config(conn, config));

    /* If s2n_negotiate fails, it usually would delay with a sleep. In order to
     * test that we don't blind when CLientHello callback fails the handshake,
     * disable blinding here */
    EXPECT_SUCCESS(s2n_connection_set_blinding(conn, S2N_SELF_SERVICE_BLINDING));

    /* Set up the connection to read from the fd */
    EXPECT_SUCCESS(s2n_connection_set_read_fd(conn, client_to_server[0]));
    EXPECT_SUCCESS(s2n_connection_set_write_fd(conn, server_to_client[1]));

    /* Negotiate the handshake. */
    EXPECT_FAILURE_WITH_ERRNO(s2n_negotiate(conn, &blocked), S2N_ERR_CANCELLED);

    /* Check that blinding was not invoked */
    EXPECT_EQUAL(s2n_connection_get_delay(conn), 0);

    /* Ensure that callback was invoked */
    EXPECT_EQUAL(client_hello_ctx.invoked, 1);

    /* Shutdown to flush alert. Expect failure as client doesn't send close
     * notify */
    EXPECT_FAILURE(s2n_shutdown(conn, &blocked));
    EXPECT_SUCCESS(s2n_connection_free(conn));

    /* Clean up */
    EXPECT_EQUAL(waitpid(-1, &status, 0), pid);
    EXPECT_EQUAL(status, 0);
    EXPECT_SUCCESS(s2n_config_free(config));
    EXPECT_SUCCESS(s2n_cert_chain_and_key_free(chain_and_key));
    free(cert_chain_pem);
    free(private_key_pem);

    END_TEST();

    return 0;
}
