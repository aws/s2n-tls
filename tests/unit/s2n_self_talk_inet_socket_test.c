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

#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#include "s2n_test.h"
#include "testlib/s2n_testlib.h"

/* There are issues with MacOS and FreeBSD so we define the constant ourselves.
 * https://stackoverflow.com/a/34042435 */
#define S2N_TEST_INADDR_LOOPBACK 0x7f000001 /* 127.0.0.1 */

const char CHAR_A = 'a';
const char CHAR_B = 'b';

/* A collection of callbacks run during inet socket self talk tests */
struct self_talk_inet_socket_callbacks {
    S2N_RESULT (*server_post_handshake_cb)(struct s2n_connection *conn);
    S2N_RESULT (*client_post_handshake_cb)(struct s2n_connection *conn);
};

S2N_RESULT s2n_noop_inet_socket_cb(struct s2n_connection *conn)
{
    return S2N_RESULT_OK;
}

static S2N_RESULT start_client(int fd, int read_pipe, const struct self_talk_inet_socket_callbacks *socket_cb)
{
    /* Setup connections */
    DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT),
            s2n_connection_ptr_free);
    DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);

    DEFER_CLEANUP(struct s2n_cert_chain_and_key * chain_and_key, s2n_cert_chain_and_key_ptr_free);
    RESULT_GUARD_POSIX(s2n_test_cert_chain_and_key_new(&chain_and_key,
            S2N_DEFAULT_TEST_CERT_CHAIN, S2N_DEFAULT_TEST_PRIVATE_KEY));

    /* Setup config */
    RESULT_GUARD_POSIX(s2n_connection_set_blinding(client_conn, S2N_SELF_SERVICE_BLINDING));
    RESULT_GUARD_POSIX(s2n_connection_set_fd(client_conn, fd));
    RESULT_GUARD_POSIX(s2n_config_set_cipher_preferences(config, "default"));
    RESULT_GUARD_POSIX(s2n_config_set_unsafe_for_testing(config));
    RESULT_GUARD_POSIX(s2n_config_add_cert_chain_and_key_to_store(config, chain_and_key));
    RESULT_GUARD_POSIX(s2n_connection_set_config(client_conn, config));

    /* Complete the handshake */
    s2n_blocked_status blocked = S2N_NOT_BLOCKED;
    RESULT_GUARD_POSIX(s2n_negotiate(client_conn, &blocked));
    RESULT_ENSURE_EQ(client_conn->actual_protocol_version, S2N_TLS12);

    RESULT_GUARD(socket_cb->client_post_handshake_cb(client_conn));

    char sync = 0;
    char recv_buffer[1] = { 0 };

    RESULT_GUARD_POSIX(read(read_pipe, &sync, 1));
    RESULT_GUARD_POSIX(s2n_recv(client_conn, recv_buffer, 1, &blocked));
    RESULT_ENSURE_EQ(memcmp(&CHAR_A, &recv_buffer[0], 1), 0);

    RESULT_GUARD_POSIX(read(read_pipe, &sync, 1));
    RESULT_GUARD_POSIX(s2n_recv(client_conn, recv_buffer, 1, &blocked));
    RESULT_ENSURE_EQ(memcmp(&CHAR_B, &recv_buffer[0], 1), 0);

    return S2N_RESULT_OK;
}

static S2N_RESULT start_server(int fd, int write_pipe, const struct self_talk_inet_socket_callbacks *socket_cb)
{
    /* Setup connections */
    DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER),
            s2n_connection_ptr_free);
    DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);

    DEFER_CLEANUP(struct s2n_cert_chain_and_key * chain_and_key, s2n_cert_chain_and_key_ptr_free);
    RESULT_GUARD_POSIX(s2n_test_cert_chain_and_key_new(&chain_and_key,
            S2N_DEFAULT_TEST_CERT_CHAIN, S2N_DEFAULT_TEST_PRIVATE_KEY));

    /* Setup config */
    RESULT_GUARD_POSIX(s2n_connection_set_blinding(server_conn, S2N_SELF_SERVICE_BLINDING));
    RESULT_ENSURE_EQ(s2n_connection_get_delay(server_conn), 0);
    RESULT_GUARD_POSIX(s2n_connection_set_fd(server_conn, fd));
    RESULT_GUARD_POSIX(s2n_config_set_cipher_preferences(config, "default"));
    RESULT_GUARD_POSIX(s2n_config_set_unsafe_for_testing(config));
    RESULT_GUARD_POSIX(s2n_config_add_cert_chain_and_key_to_store(config, chain_and_key));
    RESULT_GUARD_POSIX(s2n_connection_set_config(server_conn, config));

    /* Complete the handshake */
    s2n_blocked_status blocked = S2N_NOT_BLOCKED;
    RESULT_GUARD_POSIX(s2n_negotiate(server_conn, &blocked));
    RESULT_ENSURE_EQ(server_conn->actual_protocol_version, S2N_TLS12);

    RESULT_GUARD(socket_cb->server_post_handshake_cb(server_conn));

    char sync = 0;
    char send_buffer[1] = { 0 };

    send_buffer[0] = CHAR_A;
    RESULT_GUARD_POSIX(s2n_send(server_conn, send_buffer, 1, &blocked));
    RESULT_GUARD_POSIX(write(write_pipe, &sync, 1));

    send_buffer[0] = CHAR_B;
    RESULT_GUARD_POSIX(s2n_send(server_conn, send_buffer, 1, &blocked));
    RESULT_GUARD_POSIX(write(write_pipe, &sync, 1));

    return S2N_RESULT_OK;
}

static S2N_RESULT launch_test(const struct self_talk_inet_socket_callbacks *socket_cb)
{
    /* configure real socket */
    int listener = socket(AF_INET, SOCK_STREAM, 0);
    RESULT_GUARD_POSIX(listener);
    struct sockaddr_in saddr = { 0 };
    saddr.sin_family = AF_INET;
    saddr.sin_addr.s_addr = htonl(S2N_TEST_INADDR_LOOPBACK);
    saddr.sin_port = 0;

    /* listen on socket address */
    socklen_t addrlen = sizeof(saddr);
    RESULT_GUARD_POSIX(bind(listener, (struct sockaddr *) &saddr, addrlen));
    RESULT_GUARD_POSIX(getsockname(listener, (struct sockaddr *) &saddr, &addrlen));

    /* Used for synchronizing read and writes between client and server.
     *
     * The purpose of this mechanism is to prevent the client from reading
     * before the server has sent it. The client blocks on reading a single
     * char while the server writes a char after it has sent data and wishes
     * to unblock the client. */
    int sync_pipe[2] = { 0 };
    RESULT_GUARD_POSIX(pipe(sync_pipe));

    pid_t child = fork();
    RESULT_ENSURE(child >= 0, S2N_ERR_SAFETY);
    int status = 0;
    int fd = 0;
    if (child) {
        /* server */
        RESULT_GUARD_POSIX(listen(listener, 1));
        fd = accept(listener, NULL, NULL);
        RESULT_GUARD_POSIX(fd);

        RESULT_GUARD_POSIX(close(sync_pipe[0]));
        RESULT_GUARD(start_server(fd, sync_pipe[1], socket_cb));

        RESULT_ENSURE_EQ(waitpid(-1, &status, 0), child);
        RESULT_ENSURE_EQ(status, 0);
    } else {
        /* client */
        fd = socket(AF_INET, SOCK_STREAM, 0);
        RESULT_GUARD_POSIX(fd);

        /* wait for server to start up */
        sleep(1);
        RESULT_GUARD_POSIX(connect(fd, (struct sockaddr *) &saddr, addrlen));

        RESULT_GUARD_POSIX(close(sync_pipe[1]));
        RESULT_GUARD(start_client(fd, sync_pipe[0], socket_cb));
        exit(0);
    }

    return S2N_RESULT_OK;
}

/* This test is unique compared to our other self talk tests because it's testing
 * AF_INET socket functionality.
 *
 * When enabled, kTLS offloads the TLS protocol to the socket. It's not possible to
 * enable kTLS on an AF_UNIX socket, which is what our other self talk tests use.
 * Instead we need to use AF_INET sockets to test kTLS functionality. The use of
 * AF_INET sockets also drives the need to `fork` and create two processes (client and
 * server) to establish a TLS connection.
 */
int main(int argc, char **argv)
{
    BEGIN_TEST();

    /* SIGPIPE is received when a process tries to write to a socket which
     * has been shutdown. Ignore it and handle it gracefully. */
    signal(SIGPIPE, SIG_IGN);

    /* A regular connection */
    const struct self_talk_inet_socket_callbacks noop_inet_cb = {
        .server_post_handshake_cb = s2n_noop_inet_socket_cb,
        .client_post_handshake_cb = s2n_noop_inet_socket_cb,
    };
    EXPECT_OK(launch_test(&noop_inet_cb));

    END_TEST();
}
