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

#include "s2n.h"
#include "s2n_test.h"
#include "stdio.h"
#include "testlib/s2n_testlib.h"
#include "tls/s2n_connection.h"
#include "utils/s2n_safety.h"
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/wait.h>

#define S2N_MODE_COUNT 2
#define S2N_SECRET_TYPE_COUNT 5

pid_t child;
const char a = 'a';
const char b = 'b';
const char c = 'c';
static void terminate(void)
{
	kill(child, SIGTERM);
	exit(1);
}

static void ch_handler(int sig)
{
	  return;
}

static S2N_RESULT start_client(int fd, int sync_pipe)
{
    char read_sync;
    s2n_blocked_status blocked = 0;
    char recv_buffer[1];

    /* Setup connections */
    DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT),
            s2n_connection_ptr_free);
    DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);

    DEFER_CLEANUP(struct s2n_cert_chain_and_key *chain_and_key, s2n_cert_chain_and_key_ptr_free);
    EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&chain_and_key,
            S2N_DEFAULT_ECDSA_TEST_CERT_CHAIN, S2N_DEFAULT_ECDSA_TEST_PRIVATE_KEY));

    /* Setup config */
    EXPECT_SUCCESS(s2n_connection_set_fd(client_conn, fd));
    EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, "default_tls13"));
    EXPECT_SUCCESS(s2n_config_set_unsafe_for_testing(config));
    EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, chain_and_key));
    EXPECT_SUCCESS(s2n_config_ktls_enable(config));
    EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config));

    /* Do handshake */
    EXPECT_SUCCESS(s2n_negotiate(client_conn, &blocked));
    EXPECT_EQUAL(client_conn->actual_protocol_version, S2N_TLS13);

    read(sync_pipe, &read_sync, 1);
    printf("----------client read 1\n");
    EXPECT_SUCCESS(s2n_recv(client_conn, recv_buffer, 1, &blocked));
    EXPECT_TRUE(memcmp(&a, &recv_buffer[0], 1) == 0);

    read(sync_pipe, &read_sync, 1);
    printf("----------client read 2\n");
    EXPECT_SUCCESS(s2n_recv(client_conn, recv_buffer, 1, &blocked));
    EXPECT_TRUE(memcmp(&b, &recv_buffer[0], 1) == 0);

    return S2N_RESULT_OK;
}

static S2N_RESULT start_server(int fd, int sync_pipe)
{
    char write_sync = 0;
    s2n_blocked_status blocked = 0;
    char send_buffer[1];
    /* char recv_buffer[0xffff]; */

    /* Setup connections */
    DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER),
            s2n_connection_ptr_free);
    DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);

    DEFER_CLEANUP(struct s2n_cert_chain_and_key *chain_and_key, s2n_cert_chain_and_key_ptr_free);
    EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&chain_and_key,
            S2N_DEFAULT_ECDSA_TEST_CERT_CHAIN, S2N_DEFAULT_ECDSA_TEST_PRIVATE_KEY));

    /* Setup config */
    EXPECT_SUCCESS(s2n_connection_set_fd(server_conn, fd));
    EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, "default_tls13"));
    EXPECT_SUCCESS(s2n_config_set_unsafe_for_testing(config));
    EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, chain_and_key));
    EXPECT_SUCCESS(s2n_config_ktls_enable(config));
    EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));

    /* Do handshake */
    EXPECT_SUCCESS(s2n_negotiate(server_conn, &blocked));

    sleep(3);
    write(sync_pipe, &write_sync, 1);
    printf("----------server write1\n");
    send_buffer[0] = a;
    EXPECT_SUCCESS(s2n_send(server_conn, send_buffer, 1, &blocked));

    sleep(3);
    write(sync_pipe, &write_sync, 1);
    printf("----------server write2\n");
    send_buffer[0] = b;
    EXPECT_SUCCESS(s2n_send(server_conn, send_buffer, 1, &blocked));

    /* Verify TLS1.3 */
    EXPECT_EQUAL(server_conn->actual_protocol_version, S2N_TLS13);

    return S2N_RESULT_OK;
}

int main(int argc, char **argv)
{
    BEGIN_TEST();

    signal(SIGPIPE, SIG_IGN);
	  signal(SIGCHLD, ch_handler);

    //used for synchronizing read and writes between client and server
	  int sync_pipe[2];
	  pipe(sync_pipe);

    /* real socket */
    int listener;
    struct sockaddr_in saddr;
    socklen_t addrlen;
    int ret;
    int fd;

	  listener = socket(AF_INET, SOCK_STREAM, 0);
    EXPECT_SUCCESS(listener);
    fprintf(stderr, "server listen on fd---------- %d\n", listener);

	  memset(&saddr, 0, sizeof(saddr));
	  saddr.sin_family = AF_INET;
	  saddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	  saddr.sin_port = 0;

    EXPECT_SUCCESS(bind(listener, (struct sockaddr*)&saddr, sizeof(saddr)));
    addrlen = sizeof(saddr);
    EXPECT_SUCCESS(getsockname(listener, (struct sockaddr*)&saddr, &addrlen));

    child = fork();
    EXPECT_FALSE(child < 0);
    int status;
	  if (child) {
        /* server */
        EXPECT_SUCCESS(listen(listener, 1));
        fd = accept(listener, NULL, NULL);
        EXPECT_SUCCESS(fd);
        fprintf(stderr, "server accept fd---------- %d\n", fd);

        close(sync_pipe[0]);
        EXPECT_OK(start_server(fd, sync_pipe[1]));

        EXPECT_EQUAL(wait(&status), child);
        EXPECT_EQUAL(status, 0);
    } else {
        /* client */
        fd = socket(AF_INET, SOCK_STREAM, 0);
        EXPECT_SUCCESS(fd);

        sleep(1);
		    EXPECT_SUCCESS(connect(fd, (struct sockaddr*)&saddr, addrlen));

        fprintf(stderr, "client connect fd---------- %d\n", fd);

        close(sync_pipe[1]);
        EXPECT_OK(start_client(fd, sync_pipe[0]));
        exit(0);
    }

    /* s2n_blocked_status blocked = 0; */
    /* char send_buffer[0xffff]; */
    /* char recv_buffer[0xffff]; */

    /* KTLS KeyUpdate test */
    /* { */
    /*     const char a = 'a'; */
    /*     const char b = 'b'; */
    /*     const char c = 'c'; */

    /*     send_buffer[0] = a; */
    /*     EXPECT_SUCCESS(s2n_send(client_conn, send_buffer, 1, &blocked)); */
    /*     EXPECT_SUCCESS(s2n_recv(server_conn, recv_buffer, 1, &blocked)); */
    /*     printf("-------- %c %c %c\n", send_buffer[0], a, recv_buffer[0]); */
    /*     EXPECT_TRUE(memcmp(&a, &recv_buffer[0], 1) == 0); */

    /*     /1* -------------------------- client sends *1/ */
    /*     client_conn->key_update_pending = true; */
    /*     EXPECT_SUCCESS(s2n_key_update_send(client_conn, &blocked)); */

    /*     send_buffer[0] = b; */
    /*     EXPECT_SUCCESS(s2n_send(client_conn, send_buffer, 1, &blocked)); */
    /*     EXPECT_SUCCESS(s2n_recv(server_conn, recv_buffer, 1, &blocked)); */
    /*     printf("-------- %c %c %c\n", send_buffer[0], b, recv_buffer[0]); */
    /*     EXPECT_TRUE(memcmp(&b, &recv_buffer[0], 1) == 0); */

    /*     /1* -------------------------- server sends *1/ */
    /*     server_conn->key_update_pending = true; */
    /*     EXPECT_SUCCESS(s2n_key_update_send(server_conn, &blocked)); */

    /*     send_buffer[0] = c; */
    /*     EXPECT_SUCCESS(s2n_send(server_conn, send_buffer, 1, &blocked)); */
    /*     EXPECT_SUCCESS(s2n_recv(client_conn, recv_buffer, 1, &blocked)); */
    /*     printf("-------- %c %c %c\n", send_buffer[0], c, recv_buffer[0]); */
    /*     EXPECT_TRUE(memcmp(&c, &recv_buffer[0], 1) == 0); */

    /* } */
    /* KTLS KeyUpdate test */

    END_TEST();
}
